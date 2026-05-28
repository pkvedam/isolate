/*
 *	Process Isolator -- Control Groups
 *
 *	(c) 2012-2016 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
  CG_MEMORY = 0,
  CG_CPUACCT,
  CG_CPUSET,
  CG_NUM_CONTROLLERS,
  CG_PARENT = 256,
} cg_controller;

static char cg_name[256];
static char cg_parent_name[256];

#define CG_BUFSIZE 1024

static void
cg_makepath(char *buf, size_t len, cg_controller c UNUSED, const char *attr)
{
  const char *group = (c & CG_PARENT) ? cg_parent_name : cg_name;
  if (attr && attr[0])
    snprintf(buf, len, "%s/%s/%s", cf_cg_root, group, attr);
  else
    snprintf(buf, len, "%s/%s", cf_cg_root, group);
}

static int
cg_read(cg_controller controller, const char *attr, char *buf)
{
  int result = 0;
  int maybe = 0;
  if (attr[0] == '?')
    {
      attr++;
      maybe = 1;
    }

  char path[256];
  cg_makepath(path, sizeof(path), controller, attr);

  int fd = open(path, O_RDONLY);
  if (fd < 0)
    {
      if (maybe)
	goto fail;
      die("Cannot read %s: %m", path);
    }

  int n = read(fd, buf, CG_BUFSIZE);
  if (n < 0)
    {
      if (maybe)
	goto fail_close;
      die("Cannot read %s: %m", path);
    }
  if (n >= CG_BUFSIZE - 1)
    die("Attribute %s too long", path);
  if (n > 0 && buf[n-1] == '\n')
    n--;
  buf[n] = 0;

  if (verbose > 1)
    msg("CG: Read %s = <%s>\n", attr, buf);

  result = 1;
fail_close:
  close(fd);
fail:
  return result;
}

static int
cg_list_has_item(const char *list, const char *item)
{
  size_t n = strlen(item);
  const char *p = list;
  while ((p = strstr(p, item)))
    {
      char before = (p == list) ? ' ' : p[-1];
      char after = p[n];
      int before_ok = (before == ' ' || before == '\n' || before == '\t');
      int after_ok = (after == 0 || after == ' ' || after == '\n' || after == '\t');
      if (before_ok && after_ok)
        return 1;
      p += n;
    }
  return 0;
}

static int __attribute__((format(printf,3,4)))
cg_try_write(cg_controller controller, const char *attr, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  char buf[CG_BUFSIZE];
  int n = vsnprintf(buf, sizeof(buf), fmt, args);
  if (n >= CG_BUFSIZE)
    die("cg_try_write: Value for attribute %s is too long", attr);

  char path[256];
  cg_makepath(path, sizeof(path), controller, attr);

  int fd = open(path, O_WRONLY | O_TRUNC);
  if (fd < 0)
    {
      va_end(args);
      return 0;
    }

  int written = write(fd, buf, n);
  int saved_errno = errno;
  close(fd);
  va_end(args);

  if (written == n)
    return 1;

  errno = (written < 0) ? saved_errno : EIO;
  return 0;
}

static void
cg_enable_subtree_controller(const char *name, int required)
{
  char controllers[CG_BUFSIZE], subtree[CG_BUFSIZE];

  if (!cg_read(CG_PARENT | CG_MEMORY, "cgroup.controllers", controllers))
    die("Cannot query cgroup.controllers under %s", cg_parent_name);

  if (!cg_list_has_item(controllers, name))
    {
      if (required)
        die("Required cgroup controller '%s' is not available under %s", name, cg_parent_name);
      return;
    }

  if (!cg_read(CG_PARENT | CG_MEMORY, "cgroup.subtree_control", subtree))
    die("Cannot query cgroup.subtree_control under %s", cg_parent_name);
  if (cg_list_has_item(subtree, name))
    return;

  if (!cg_try_write(CG_PARENT | CG_MEMORY, "cgroup.subtree_control", "+%s\n", name))
    {
      int e = errno;
      if (cg_read(CG_PARENT | CG_MEMORY, "cgroup.subtree_control", subtree) &&
          cg_list_has_item(subtree, name))
        return;

      if (!required && (e == ENOENT || e == EINVAL || e == EBUSY || e == EPERM || e == EROFS))
        return;

      die("Cannot enable cgroup controller '%s' in parent %s (%s). "
          "Set cg_parent to a delegated cgroup if needed.",
          name, cg_parent_name, strerror(e));
    }
}

static void __attribute__((format(printf,3,4)))
cg_write(cg_controller controller, const char *attr, const char *fmt, ...)
{
  int maybe = 0;
  if (attr[0] == '?')
    {
      attr++;
      maybe = 1;
    }

  va_list args;
  va_start(args, fmt);

  char buf[CG_BUFSIZE];
  int n = vsnprintf(buf, sizeof(buf), fmt, args);
  if (n >= CG_BUFSIZE)
    die("cg_write: Value for attribute %s is too long", attr);

  if (verbose > 1)
    msg("CG: Write %s = %s", attr, buf);

  char path[256];
  cg_makepath(path, sizeof(path), controller, attr);

  int fd = open(path, O_WRONLY | O_TRUNC);
  if (fd < 0)
    {
      if (maybe)
	goto fail;
      else
	die("Cannot write %s: %m", path);
    }

  int written = write(fd, buf, n);
  if (written < 0)
    {
      if (maybe)
	goto fail_close;
      else
	die("Cannot set %s to %s: %m", path, buf);
    }
  if (written != n)
    die("Short write to %s (%d out of %d bytes)", path, written, n);

fail_close:
  close(fd);
fail:
  va_end(args);
}

void
cg_init(void)
{
  if (!cg_enable)
    return;

  if (!dir_exists(cf_cg_root))
    die("Control group filesystem at %s not mounted", cf_cg_root);

  if (cf_cg_parent)
    {
      snprintf(cg_name, sizeof(cg_name), "%s/box-%d", cf_cg_parent, box_id);
      snprintf(cg_parent_name, sizeof(cg_parent_name), "%s", cf_cg_parent);
    }
  else
    {
      snprintf(cg_name, sizeof(cg_name), "box-%d", box_id);
      strcpy(cg_parent_name, ".");
    }
  msg("Using control group %s under parent %s\n", cg_name, cg_parent_name);
}

void
cg_prepare(void)
{
  if (!cg_enable)
    return;

  struct stat st;
  char buf[CG_BUFSIZE];
  char path[256];
  struct cf_per_box *cf = cf_current_box();

  cg_enable_subtree_controller("memory", 1);
  cg_enable_subtree_controller("cpu", 1);
  cg_enable_subtree_controller("cpuset", 0);

  cg_makepath(path, sizeof(path), CG_MEMORY, "");
  if (stat(path, &st) >= 0 || errno != ENOENT)
    {
      msg("Control group %s already exists, trying to empty it.\n", path);
      if (rmdir(path) < 0)
	die("Failed to reset control group %s: %m", path);
    }
  if (mkdir(path, 0777) < 0)
    die("Failed to create control group %s: %m", path);

  // If cpuset is available, set up allowed cpus and memory nodes.
  // If per-box configuration exists, use it; otherwise, inherit the settings
  // from the parent cgroup.
  if (cg_read(CG_PARENT | CG_CPUSET, "?cpuset.cpus.effective", buf))
    cg_write(CG_CPUSET, "?cpuset.cpus", "%s", cf->cpus ? cf->cpus : buf);
  if (cg_read(CG_PARENT | CG_CPUSET, "?cpuset.mems.effective", buf))
    cg_write(CG_CPUSET, "?cpuset.mems", "%s", cf->mems ? cf->mems : buf);
}

void
cg_enter(void)
{
  if (!cg_enable)
    return;

  msg("Entering control group %s\n", cg_name);

  cg_write(CG_MEMORY, "cgroup.procs", "%d\n", (int) getpid());

  if (cg_memory_limit)
    {
      cg_write(CG_MEMORY, "memory.max", "%lld\n", (long long) cg_memory_limit << 10);
      cg_write(CG_MEMORY, "?memory.swap.max", "%lld\n", (long long) cg_memory_limit << 10);
    }
}

int
cg_get_run_time_ms(void)
{
  if (!cg_enable)
    return 0;

  char buf[CG_BUFSIZE];
  if (!cg_read(CG_CPUACCT, "cpu.stat", buf))
    return 0;

  unsigned long long usec = 0;
  char *s = buf;
  while (s)
    {
      if (sscanf(s, "usage_usec %llu", &usec) == 1)
        return usec / 1000;
      s = strchr(s, '\n');
      if (s)
	s++;
    }
  return 0;
}

void
cg_stats(void)
{
  if (!cg_enable)
    return;

  char buf[CG_BUFSIZE];

  // Memory usage statistics
  unsigned long long mem = 0;
  if (cg_read(CG_MEMORY, "?memory.peak", buf))
    mem = atoll(buf);
  if (mem)
    meta_printf("cg-mem:%lld\n", mem >> 10);

  // OOM kill detection
  if (cg_read(CG_MEMORY, "?memory.events", buf))
    {
      int oom_killed = 0;
      char *s = buf;
      while (s)
	{
	  if (sscanf(s, "oom_kill %d", &oom_killed) == 1 && oom_killed)
	    {
	      meta_printf("cg-oom-killed:1\n");
	      break;
	    }
	  s = strchr(s, '\n');
	  if (s)
	    s++;
	}
    }
}

void
cg_remove(void)
{
  char buf[CG_BUFSIZE];
  char path[256];

  if (!cg_enable)
    return;

  // The cgroup can be non-existent at this moment (e.g., --cleanup before the first --init).
  if (!cg_read(CG_MEMORY, "?cgroup.procs", buf))
    return;

  if (buf[0])
    die("Some tasks left in cgroup %s, failed to remove it", cg_name);

  cg_makepath(path, sizeof(path), CG_MEMORY, "");
  if (rmdir(path) < 0)
    die("Cannot remove control group %s: %m", path);
}
