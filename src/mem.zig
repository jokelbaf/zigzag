const std = @import("std");
const windows = std.os.windows;
const PROT = std.posix.PROT;
const target = @import("builtin").os.tag;
const kernel32 = @import("kernel32.zig");
const procmap = switch (target) {
    .windows => void,
    else => @import("procmap.zig"),
};

pub const Protection = packed struct {
    execute: bool = false,
    write: bool = false,
    read: bool = false,

    pub const everything: Protection = .{ .read = true, .write = true, .execute = true };

    fn posixFlags(p: Protection) PROT {
        return .{ .READ = p.read, .WRITE = p.write, .EXEC = p.execute };
    }

    fn winapiFlags(p: Protection) windows.PAGE {
        return windows.PAGE.fromProtection(.{ .read = p.read, .write = p.write, .execute = p.execute }) orelse unreachable;
    }

    fn fromWinapi(f: windows.PAGE) Protection {
        return .{
            .read = f.READONLY or f.READWRITE or f.WRITECOPY or f.EXECUTE_READ or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
            .write = f.READWRITE or f.WRITECOPY or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
            .execute = f.EXECUTE or f.EXECUTE_READ or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
        };
    }

    fn fromPosix(f: PROT) Protection {
        return .{
            .read = f.READ,
            .write = f.WRITE,
            .execute = f.EXEC,
        };
    }

    test {
        const a: Protection = .everything;
        try std.testing.expectEqual(PROT{ .WRITE = true, .READ = true, .EXEC = true }, a.posixFlags());

        const b: Protection = .{ .read = true };
        try std.testing.expectEqual(PROT{ .READ = true }, b.posixFlags());

        const c: Protection = .{ .write = true };
        try std.testing.expectEqual(PROT{ .WRITE = true }, c.posixFlags());

        const d: Protection = .{ .execute = true };
        try std.testing.expectEqual(PROT{ .EXEC = true }, d.posixFlags());

        const e: Protection = .{};
        try std.testing.expectEqual(PROT{}, e.posixFlags());
    }
};

pub const MapError = switch (target) {
    .windows => error{ AccessDenied, OutOfMemory, Unexpected },
    else => std.posix.MMapError,
};

pub const ProtectError = switch (target) {
    .windows => error{ AccessDenied, Unexpected },
    .linux => std.process.ProtectMemoryError || procmap.ProcmapQuery.QueryError,
    else => unreachable,
};

pub fn map(addr: ?*anyopaque, size: usize, prot: Protection) MapError![]align(std.heap.page_size_min) u8 {
    return switch (target) {
        .windows => blk: {
            var base = addr;
            var length = size;
            switch (windows.ntdll.NtAllocateVirtualMemory(windows.current_process, @ptrCast(&base), 0, &length, .{ .COMMIT = true, .RESERVE = true }, prot.winapiFlags())) {
                .SUCCESS => break :blk @as([*]align(std.heap.page_size_min) u8, @ptrCast(@alignCast(base.?)))[0..size],
                .ACCESS_DENIED => return error.AccessDenied,
                .NO_MEMORY, .CONFLICTING_ADDRESSES, .COMMITMENT_LIMIT => return error.OutOfMemory,
                else => |status| return windows.unexpectedStatus(status),
            }
        },
        .linux => std.posix.mmap(@ptrCast(@alignCast(addr)), size, prot.posixFlags(), .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0),
        else => unreachable,
    };
}

pub fn unmap(mem: []align(std.heap.page_size_min) u8) void {
    return switch (target) {
        .windows => {
            var base: windows.PVOID = mem.ptr;
            var size: usize = 0;
            const status = windows.ntdll.NtFreeVirtualMemory(windows.current_process, &base, &size, .{ .RELEASE = true });
            std.debug.assert(status == .SUCCESS);
        },
        .linux => std.posix.munmap(mem),
        else => unreachable,
    };
}

pub fn protect(mem: []align(std.heap.page_size_min) u8, prot: Protection) ProtectError!Protection {
    switch (target) {
        .windows => {
            var base: ?windows.PVOID = mem.ptr;
            var size = mem.len;
            var prev: windows.PAGE = undefined;
            switch (windows.ntdll.NtProtectVirtualMemory(windows.current_process, &base, &size, prot.winapiFlags(), &prev)) {
                .SUCCESS => {},
                .INVALID_ADDRESS, .ACCESS_DENIED => return error.AccessDenied,
                else => |status| return windows.unexpectedStatus(status),
            }

            return .fromWinapi(prev);
        },
        .linux => {
            var q: procmap.ProcmapQuery = .{ .query_addr = @intFromPtr(mem.ptr), .query_flags = .{} };
            try q.query();

            try std.process.protectMemory(mem, .{ .read = prot.read, .write = prot.write, .execute = prot.execute });
            return q.vma_flags.prot();
        },
        else => unreachable,
    }
}

var mmap_min_addr: std.atomic.Value(usize) = .init(std.math.maxInt(usize));
var allocation_granularity: std.atomic.Value(usize) = .init(0);

pub const InitError = switch (target) {
    .windows => error{},
    .linux => std.posix.OpenError || std.posix.ReadError || std.fmt.ParseIntError,
    else => unreachable,
};

pub fn init() InitError!void {
    if (mmap_min_addr.load(.acquire) != std.math.maxInt(usize)) return;

    switch (target) {
        .windows => {
            var system_info: kernel32.SYSTEM_INFO = undefined;
            kernel32.GetSystemInfo(&system_info);
            allocation_granularity.store(system_info.dwAllocationGranularity, .monotonic);
            mmap_min_addr.store(@intFromPtr(system_info.lpMinimumApplicationAddress), .release);
        },
        .linux => {
            const min_addr_path = "/proc/sys/vm/mmap_min_addr";
            var buf: [32]u8 = undefined;
            const fd = try std.posix.openat(std.posix.AT.FDCWD, min_addr_path, .{ .CLOEXEC = true }, 0);
            defer std.Io.Threaded.closeFd(fd);

            const size = try std.posix.read(fd, &buf);
            const address = try std.fmt.parseInt(usize, std.mem.trim(u8, buf[0..size], "\r\n"), 10);
            mmap_min_addr.store(address, .release);
        },
        else => unreachable,
    }
}

pub const Range = struct {
    /// inclusive
    from: usize,
    /// inclusive
    to: usize,

    pub fn contains(r: Range, addr: usize) bool {
        return addr >= r.from and addr <= r.to;
    }

    pub fn intersects(a: Range, b: Range) bool {
        return a.from <= b.to and b.from <= a.to;
    }

    /// Construct the range [origin - x; origin + x]
    pub fn symmetric(origin: usize, x: u32) Range {
        return .{
            .from = origin -| x,
            .to = origin +| x,
        };
    }

    /// Calculate max and min possible addresses for the trampoline relative to the target address
    pub fn rip(addr: usize) Range {
        const min_addr = mmap_min_addr.load(.acquire);
        var bounds = symmetric(addr, std.math.maxInt(i32));
        bounds.from = @max(bounds.from, min_addr);
        return bounds;
    }

    test {
        {
            const a: Range = .{ .from = 0, .to = 10 };
            const b: Range = .{ .from = 5, .to = 15 };
            try std.testing.expect(a.intersects(b));
            try std.testing.expect(b.intersects(a));
        }

        {
            const a: Range = .{ .from = 5, .to = 10 };
            const b: Range = .{ .from = 4, .to = 6 };
            try std.testing.expect(b.intersects(a));
        }
    }
};

pub const QueryError = switch (target) {
    .windows => error{Unexpected},
    .linux => procmap.ProcmapQuery.QueryError,
    else => unreachable,
};

/// Returns the starting address of a page that starts within the range
fn findUnmappedAreaWithinLinux(bounds: Range, gap_size: usize) QueryError!?usize {
    const page_size = std.heap.pageSize();
    const max_start = bounds.to - (gap_size - 1);
    var q: procmap.ProcmapQuery = .{
        .query_addr = std.mem.alignBackward(usize, std.math.add(usize, bounds.from, page_size - 1) catch return null, page_size),
        .query_flags = .{ .covering_or_next_vma = true },
    };

    while (q.query_addr <= max_start) {
        q.query() catch |err| switch (err) {
            error.NotFound => return q.query_addr,
            else => return err,
        };

        if (q.vma_start > q.query_addr and q.vma_start - q.query_addr >= gap_size) {
            return q.query_addr;
        }

        q.query_addr = q.vma_end;
    }

    return null;
}

/// Returns an address contained within a page that starts within the provided range
fn findUnmappedAreaWithinWindows(bounds: Range, gap_size: usize) QueryError!?usize {
    const granularity = allocation_granularity.load(.monotonic);
    const max_start = bounds.to - (gap_size - 1);
    var probe_address = std.mem.alignBackward(usize, std.math.add(usize, bounds.from, granularity - 1) catch return null, granularity);
    while (probe_address <= max_start) {
        var memory_info: kernel32.MEMORY_BASIC_INFORMATION = undefined;
        const info_size = kernel32.VirtualQuery(@ptrFromInt(probe_address), &memory_info, @sizeOf(@TypeOf(memory_info)));

        if (info_size == 0) {
            return error.Unexpected;
        }

        const region_end = std.math.add(usize, @intFromPtr(memory_info.BaseAddress), memory_info.RegionSize) catch return null;
        if (region_end <= probe_address) return error.Unexpected;

        if (memory_info.State == kernel32.MEM_FREE and region_end - probe_address >= gap_size) {
            return probe_address;
        }

        probe_address = std.mem.alignBackward(usize, std.math.add(usize, region_end, granularity - 1) catch return null, granularity);
    }

    return null;
}

/// bounds: min & max address where we're looking for an unallocated vma
/// size: minimum size of the vma required
pub fn findUnmappedAreaWithin(bounds: Range, size: usize) QueryError!?usize {
    if (bounds.from > bounds.to or size == 0 or size - 1 > bounds.to - bounds.from) return null;

    return switch (target) {
        .windows => findUnmappedAreaWithinWindows(bounds, size),
        .linux => findUnmappedAreaWithinLinux(bounds, size),
        else => unreachable,
    };
}

pub fn delta(a: usize, b: usize) isize {
    return switch (a > b) {
        true => @intCast(a - b),
        false => @as(isize, @intCast(b - a)) * -1,
    };
}
