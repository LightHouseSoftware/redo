/+ Traslation of shell version of djb's redo build system by Jeff Pratt (https://github.com/jecxjo/redo/blob/master/redo)
#
# Written by Jeff Parent (original shell version)
# Translated by Oleg Bakharev
# Released as Public Domain
# Version: 0.0.3
# Date: Fri Jul 25 20:32:00 2021
+/

import std.algorithm;
import std.file;
import std.format;
import std.path;
import std.process;
import std.stdio;
import std.string : replace, strip;

alias error = function(string message) {
	format("\u001b[31m\u001b[49m\u001b[1mError:\u001b[0m\u001b[97m\u001b[49m\u001b[1m %s \u001b[0m", message).writeln;
};

alias info = function(string message) {
	format("\u001b[32m\u001b[49m\u001b[1mInfo:\u001b[0m\u001b[97m\u001b[49m\u001b[1m %s \u001b[0m", message).writeln;
};

alias log = function(string message) {
	format("\u001b[34m\u001b[49m\u001b[1mLog:\u001b[0m\u001b[97m\u001b[49m\u001b[1m %s \u001b[0m", message).writeln;
};

alias warning = function(string message) {
	format("\u001b[33m\u001b[49m\u001b[1mWarning:\u001b[0m\u001b[97m\u001b[49m\u001b[1m %s \u001b[0m", message).writeln;
};

alias onlyFiles = function(string directoryPath) {
	return directoryPath.dirEntries(SpanMode.shallow).filter!`a.isFile`;
};

extern (C)
{
    import core.sys.posix.fcntl : O_RDONLY;
    import core.sys.posix.sys.types : off_t, ssize_t;

    import std.conv : to;

    extern (C) int open(scope const(char*) pathname, int flags) pure nothrow @nogc;
    extern (C) ssize_t pread(int fd, void* buf, size_t count, off_t offset);
    extern (C) int close(int fd);

    extern (C) void* memset(scope return void* s, int c, ulong n) pure nothrow @nogc;
    extern (C) void* memcpy(scope return void* s1, scope const(void*) s2, ulong n) pure nothrow @nogc;

    extern(C) struct sha256
    {
        ulong len;
        uint[8] h;
        ubyte[64] buf;
    };

    uint ror(uint n, int k) pure nothrow @nogc
    {
        return (n >> k) | (n << (32 - k));
    }

    uint Ch(uint x, uint y, uint z) pure nothrow @nogc
    {
        return (z ^ (x & (y ^ z)));
    }

    uint Maj(uint x, uint y, uint z) pure nothrow @nogc
    {
        return ((x & y) | (z & (x | y)));
    }

    uint S0(uint x) pure nothrow @nogc
    {
        return (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22));
    }

    uint S1(uint x) pure nothrow @nogc
    {
        return (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25));
    }

    uint R0(uint x) pure nothrow @nogc
    {
        return (ror(x, 7) ^ ror(x, 18) ^ (x >> 3));
    }

    uint R1(uint x) pure nothrow @nogc
    {
        return (ror(x, 17) ^ ror(x, 19) ^ (x >> 10));
    }

    enum uint[64] K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    void processblock(ref sha256 s, ubyte* buf) nothrow @nogc
    {
        uint[64] W;
        uint t1, t2, a, b, c, d, e, f, g, h;
        int i;

        for (i = 0; i < 16; i++)
        {
            W[i] = cast(uint)(buf[4 * i] << 24);
            W[i] |= cast(uint)(buf[4 * i + 1] << 16);
            W[i] |= cast(uint)(buf[4 * i + 2] << 8);
            W[i] |= buf[4 * i + 3];
        }
        for (; i < 64; i++)
            W[i] = R1(W[i - 2]) + W[i - 7] + R0(W[i - 15]) + W[i - 16];
        a = s.h[0];
        b = s.h[1];
        c = s.h[2];
        d = s.h[3];
        e = s.h[4];
        f = s.h[5];
        g = s.h[6];
        h = s.h[7];
        for (i = 0; i < 64; i++)
        {
            t1 = h + S1(e) + Ch(e, f, g) + K[i] + W[i];
            t2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        s.h[0] += a;
        s.h[1] += b;
        s.h[2] += c;
        s.h[3] += d;
        s.h[4] += e;
        s.h[5] += f;
        s.h[6] += g;
        s.h[7] += h;
    }

    void pad(ref sha256 s) nothrow @nogc
    {
        uint r = s.len % 64;
        auto ptr = s.buf.ptr;

        s.buf[r++] = 0x80;
        if (r > 56)
        {
            memset(ptr + r, 0, 64 - r);
            r = 0;
            processblock(s, s.buf.ptr);
        }
        memset(ptr + r, 0, 56 - r);
        s.len *= 8;
        s.buf[56] = cast(ubyte)(s.len >> 56);
        s.buf[57] = cast(ubyte)(s.len >> 48);
        s.buf[58] = cast(ubyte)(s.len >> 40);
        s.buf[59] = cast(ubyte)(s.len >> 32);
        s.buf[60] = cast(ubyte)(s.len >> 24);
        s.buf[61] = cast(ubyte)(s.len >> 16);
        s.buf[62] = cast(ubyte)(s.len >> 8);
        s.buf[63] = cast(ubyte)(s.len);
        processblock(s, s.buf.ptr);
    }

    void sha256_init(ref sha256 s) pure nothrow @nogc
    {
        s.len = 0;
        s.h[0] = 0x6a09e667;
        s.h[1] = 0xbb67ae85;
        s.h[2] = 0x3c6ef372;
        s.h[3] = 0xa54ff53a;
        s.h[4] = 0x510e527f;
        s.h[5] = 0x9b05688c;
        s.h[6] = 0x1f83d9ab;
        s.h[7] = 0x5be0cd19;
    }

    void sha256_sum(ref sha256 s, ubyte* md) nothrow @nogc
    {
        int i;

        pad(s);
        for (i = 0; i < 8; i++)
        {
            md[4 * i] = cast(ubyte)(s.h[i] >> 24);
            md[4 * i + 1] = cast(ubyte)(s.h[i] >> 16);
            md[4 * i + 2] = cast(ubyte)(s.h[i] >> 8);
            md[4 * i + 3] = cast(ubyte)(s.h[i]);
        }
    }

    void sha256_update(ref sha256 s, const void* m, ulong len) nothrow @nogc
    {
        ubyte* p = cast(ubyte*) m;
        uint r = s.len % 64;
        auto ptr = s.buf.ptr;

        s.len += len;
        if (r)
        {
            if (len < 64 - r)
            {
                memcpy(ptr + r, p, len);
                return;
            }
            memcpy(ptr + r, p, 64 - r);
            len -= 64 - r;
            p += 64 - r;
            processblock(s, s.buf.ptr);
        }
        for (; len >= 64; len -= 64, p += 64)
            processblock(s, p);
        memcpy(ptr, p, len);
    }

    char* hashfile(int fd) @system
    {
        static char[16] hex = "0123456789abcdef";
        static char[65] asciihash;

        sha256 ctx;
        ulong off = 0;
        char[4096] buf;
        char* a;
        char[32] hash;
        int i;
        ssize_t r;

        sha256_init(ctx);

        while ((r = pread(fd, cast(void*) buf, buf.sizeof, off)) > 0)
        {
            sha256_update(ctx, cast(void*) buf, r);
            off += r;
        }

        sha256_sum(ctx, cast(ubyte*) hash);

        for (i = 0, a = asciihash.ptr; i < 32; i++)
        {
            *a++ = hex[hash[i] / 16];
            *a++ = hex[hash[i] % 16];
        }
        *a = 0;

        return asciihash.ptr;
    }

    string sha256sum(string filepath) @trusted {
        char* filename = cast(char*) filepath.dup;
        int fd = open(filename, O_RDONLY);
        
        scope (exit)
        {
            fd.close;
        }

        char* hash = hashfile(fd);

        return hash.to!string;
    };
}

alias getExtension = function(string filepath) {
		return filepath.extension.replace(".", "");
};

auto lineFromFile(string filePath)
{
	return File(filePath, `r`).readln.strip;
}

auto lineToFile(string line, string filePath)
{
	File(filePath, `w`).writeln(line);
}

void main(string[] arguments)
{
	enum string metaDirectory = `.redo`;

	auto cleanChangeSum(string dependency, string target)
	{
		auto changeDirectory = format(metaDirectory ~ "/%s/change/", target);
		foreach (a; changeDirectory.onlyFiles)
		{
			if (lineFromFile(a) == dependency)
			{
				remove(a);
			}
		}
	}
	
	auto cleanCreateSum(string dependency, string target)
	{
		auto createDirectory = format(metaDirectory ~ "/%s/create/", target);
		foreach (b; createDirectory.onlyFiles)
		{
			if (lineFromFile(b) == dependency)
			{
				remove(b);
			}
		}
	}
	
	auto cleanAll(string target)
	{
		auto targetDirectory = metaDirectory ~ "/" ~ target;
		if (targetDirectory.exists)
		{
			foreach (w; targetDirectory.onlyFiles)
			{
				remove(w);
			}
		}
	}
	
	auto getChangeSum(string dependency, string target)
	{
		string changeSum;
		auto changeDirectory = format(metaDirectory ~ "/%s/change/", target);
		
		foreach (c; changeDirectory.onlyFiles)
		{
			if (lineFromFile(c) == dependency)
			{
				changeSum = baseName(c);
				break;
			}
		}
		
		return changeSum;
	}
	
	auto upToDate(string dependency, string target)
	{
		string oldSum;
		auto changeDirectory = format(metaDirectory ~ "/%s/change/", target);
		
		foreach (d; changeDirectory.onlyFiles)
		{	
			if (lineFromFile(d) == dependency)
			{
				oldSum = baseName(d);
				break;
			}
		}
		
		return (sha256sum(dependency) == oldSum);
	}
	
	auto doPath(string target)
	{
		string doFilePath;
		
		if (target.getExtension != "do")
		{
			if ((target ~ ".do").exists)
			{
				doFilePath = target ~ ".do";
			}
			else
			{
				auto path = format(`%s/default.%s.do`, target.dirName, target.getExtension);
				if (path.exists)
				{
					doFilePath = path;
				}
			}
		}
		
		return doFilePath;
	}
	
	auto genChangeSum(string dependency, string target)
	{
		cleanChangeSum(dependency, target);
		auto path = format(metaDirectory ~ "/%s/change/%s", target, sha256sum(dependency));
		lineToFile(dependency, path);
	}
	
	auto genCreateSum(string dependency, string target)
	{
		cleanCreateSum(dependency, target);
		auto path = format(metaDirectory ~ "/%s/create/%s", target, sha256sum(dependency));
		lineToFile(dependency, path);
	}
	
	auto getShebang(string filepath)
	{
		string shebang;

		foreach (line; File(filepath, `r`).byLine)
		{
			if (startsWith(cast(string) line, "#!"))
			{
				shebang = strip(cast(string) line);
				break;
			}
		}
		
		return shebang;
	}
	
	auto doRedo(string target)
	{
		string tmp = target ~ `---redoing`;
		string doFilePath = doPath(target);
		
		auto createDirectory = format(metaDirectory ~ `/%s/create/`, target);
		auto changeDirectory = format(metaDirectory ~ `/%s/change/`, target);
		
		if (!createDirectory.exists)
		{
			mkdirRecurse(createDirectory);
		}
		
		if (!changeDirectory.exists)
		{
			mkdirRecurse(changeDirectory);
		}
		
		if (doFilePath == "")
		{
			if (!target.exists)
			{
				error(format(`No .do file found for target: %s`, target));
				return;
			}
		}
		else
		{
			bool trigger;
			
			bool isPrepared = (upToDate(doFilePath, target) || (target.exists));
			
			if (!isPrepared)
			{
				trigger = true;
			}
			
			if (!trigger)
			{
				foreach (e; createDirectory.onlyFiles)
				{
					auto dependency = lineFromFile(e);
					
					if (dependency.exists)
					{
						warning(format(`%s exists but should be created`, dependency));
						return;
					}
					else
					{
						trigger = true;
					}
				}
			}
			
			if (!trigger)
			{
				foreach (f; changeDirectory.onlyFiles)
				{
						auto dependency = lineFromFile(f);
						auto shell = executeShell(`REDO_TARGET="%s" redo-ifchange "%s"`.format(target, dependency));
						
						if (baseName(f) != getChangeSum(dependency, target))
						{
							trigger = true;
						}
				}
			}
		
			if (trigger)
			{
				info(format(`redo %s`, target));
				cleanAll(target);
				genChangeSum(doFilePath, target);
				
				string cmd = getShebang(doFilePath);
				string rcmd;
			
				if (cmd == "")
				{
					rcmd = format(
						`PATH=.:$PATH REDO_TARGET="%s" sh -e "%s" 0 "%s" "%s" > "%s"`, target, doFilePath, baseName(target), tmp, tmp
					);
				}
				else
				{
					rcmd = format(
						`PATH=.:$PATH REDO_TARGET="%s" sh -c "%s" "%s" 0 "%s" "%s" > "%s"`, target, cmd, doFilePath, baseName(target), tmp, tmp
					);
				}
				info(format(`[build command]: %s`, rcmd));
				auto rc = executeShell(rcmd);
				
				if (rc.status != 0)
				{
					error(format(`Redo script exited with a non-zero exit code: %d`, rc.status));
					error(rc.output);
					remove(tmp);
					info(format(`[removing temporary file]: %s`, tmp));
				}
				else
				{
					if (tmp.exists)
					{
						if (tmp.getSize == 0)
						{
							info(format(`[removing]: %s`, tmp));
							remove(tmp);
						}
						else
						{
							info(format(`[copying]: from %s to %s`, tmp, target));
							copy(tmp, target);
						}
					}
				}
			}
		}
	}
	
	string programName = arguments[0];
	string[] targets = arguments[1..$];

	switch (programName)
	{
		case "redo-ifchange":
			if (environment.get("REDO_TARGET", "") == "")
			{
				error(`REDO_TARGET not set`);
				return;
			}
			foreach (target; targets)
			{
				doRedo(target);
				string redoTarget = environment.get("REDO_TARGET", "");
				
				if (!upToDate(target, redoTarget))
				{
					genChangeSum(target, redoTarget);
				}
			}
			break;
		case "redo-ifcreate":
			if (environment.get("REDO_TARGET", "") == "")
			{
				error(`REDO_TARGET not set`);
				return;
			}
			foreach (target; targets)
			{
				string redoTarget = environment.get("REDO_TARGET", "");
				if (target.exists)
				{
					warning(format(`%s exists but should be created`, target));
				}
				doRedo(target);
				if (target.exists)
				{
					genCreateSum(target, redoTarget);
				}
			}
			break;
		default:
			foreach (target; targets)
			{
				environment["REDO_TARGET"] = target;
				doRedo(target);
			}
			break;
	}
}
