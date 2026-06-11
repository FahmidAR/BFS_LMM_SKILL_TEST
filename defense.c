/*
 * defense.c — Buffer Overflow Defense & Input Sanitization Demo
 *
 * Compile (with AddressSanitizer + UBSan for full verification):
 *   gcc -fsanitize=address,undefined -Wall -Wextra -g -o defense defense.c
 *
 * What this file demonstrates
 * ============================
 *  1. safe_strcpy   — bounded string copy that never overruns the dest buffer.
 *  2. safe_read     — fgets-based stdin reader that refuses oversized input.
 *  3. sanitize_input— strips non-printable bytes and shell metacharacters,
 *                     then prints a [SANITIZED] notice listing every removal.
 *  4. safe_int_parse— converts a string to int with range enforcement.
 *  5. demo_overflow_guard — shows the guards firing on bad inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/* ------------------------------------------------------------------ */
/* 1. Safe Bounded String Copy                                         */
/* ------------------------------------------------------------------ */

/*
 * safe_strcpy — copies at most (dest_size - 1) bytes from src into dest
 * and always NUL-terminates.  Returns 1 if the source was truncated,
 * 0 on clean copy.
 *
 * DEFENSE: replaces strcpy/strcat which have no length parameter and
 * will blindly write past the end of dest.
 */
int safe_strcpy(char *dest, size_t dest_size, const char *src)
{
    if (!dest || dest_size == 0) return -1;
    if (!src)  { dest[0] = '\0'; return 0; }

    size_t src_len = strlen(src);
    int truncated  = (src_len >= dest_size);

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';   /* guarantee NUL even if truncated */

    if (truncated) {
        fprintf(stderr,
            "[OVERFLOW GUARD] safe_strcpy: source length %zu truncated to %zu "
            "to fit dest buffer.\n",
            src_len, dest_size - 1);
    }
    return truncated;
}

/* ------------------------------------------------------------------ */
/* 2. Safe Stdin Reader                                                */
/* ------------------------------------------------------------------ */

/*
 * safe_read — reads one line from stdin into buf[buf_size].
 * Uses fgets (bounded read) and rejects input longer than the buffer.
 * Returns 1 on success, 0 on EOF/error, -1 if input was too long.
 *
 * DEFENSE: never use gets() — it has no length limit and is the
 * textbook buffer overflow vector.  fgets stops at buf_size-1 bytes.
 */
int safe_read(char *buf, size_t buf_size)
{
    if (!buf || buf_size < 2) return 0;

    if (!fgets(buf, (int)buf_size, stdin)) return 0;

    size_t len = strlen(buf);

    /* fgets leaves '\n' in buf when the line fit; if it's missing the
       line was longer than buf_size — discard the rest and warn. */
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';   /* strip newline */
        return 1;
    }

    /* Drain the remainder of the overlong line */
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    fprintf(stderr,
        "[OVERFLOW GUARD] safe_read: input exceeded buffer (%zu bytes). "
        "Input truncated and remainder discarded.\n",
        buf_size - 1);
    buf[buf_size - 1] = '\0';
    return -1;
}

/* ------------------------------------------------------------------ */
/* 3. Input Sanitization                                               */
/* ------------------------------------------------------------------ */

/*
 * sanitize_input — removes every byte that is either:
 *   - non-printable (outside 0x20–0x7E), or
 *   - a shell metacharacter (; | & ` $ \ " ')
 * Edits buf in-place and prints a [SANITIZED] message for each removal.
 *
 * DEFENSE: prevents command-injection and format-string attacks that
 * exploit unsanitized data passed to system(), popen(), printf, etc.
 */
void sanitize_input(char *buf, size_t buf_size)
{
    if (!buf || buf_size == 0) return;

    /* Shell metacharacters that must never reach a shell or format string */
    const char *BLOCKED = ";|&`$\\\"'%";

    size_t src = 0, dst = 0;
    int any_removed = 0;

    while (buf[src] != '\0' && src < buf_size - 1) {
        unsigned char c = (unsigned char)buf[src];

        int printable = (c >= 0x20 && c <= 0x7E);
        int blocked   = (strchr(BLOCKED, c) != NULL);

        if (printable && !blocked) {
            buf[dst++] = buf[src];
        } else {
            fprintf(stderr,
                "[SANITIZED] Removed character 0x%02X ('%c') at position %zu\n",
                c, isprint(c) ? c : '?', src);
            any_removed = 1;
        }
        src++;
    }
    buf[dst] = '\0';

    if (any_removed) {
        fprintf(stderr,
            "[SANITIZED] Input was modified. Clean value: \"%s\"\n", buf);
    } else {
        printf("[SANITIZE CHECK] Input is clean: \"%s\"\n", buf);
    }
}

/* ------------------------------------------------------------------ */
/* 4. Safe Integer Parsing with Range Check                            */
/* ------------------------------------------------------------------ */

/*
 * safe_int_parse — converts str to a long and checks it falls within
 * [min, max].  Returns 1 on success (stores result in *out), 0 on error.
 *
 * DEFENSE: atoi() has no error detection and silently returns 0 on
 * bad input.  strtol detects overflow and non-numeric input.
 */
int safe_int_parse(const char *str, long min, long max, long *out)
{
    if (!str || !out) return 0;

    char *end;
    errno = 0;
    long val = strtol(str, &end, 10);

    if (errno != 0 || end == str || *end != '\0') {
        fprintf(stderr,
            "[INPUT ERROR] \"%s\" is not a valid integer.\n", str);
        return 0;
    }
    if (val < min || val > max) {
        fprintf(stderr,
            "[RANGE GUARD] Value %ld is outside allowed range [%ld, %ld].\n",
            val, min, max);
        return 0;
    }
    *out = val;
    return 1;
}

/* ------------------------------------------------------------------ */
/* 5. Demonstration                                                    */
/* ------------------------------------------------------------------ */

static void print_separator(const char *title)
{
    printf("\n=== %s ===\n", title);
}

int main(void)
{
    printf("Buffer Overflow Defense & Input Sanitization Demo\n");
    printf("==================================================\n");

    /* --- Demo 1: safe_strcpy ---------------------------------------- */
    print_separator("safe_strcpy");

    char small[8];
    safe_strcpy(small, sizeof(small), "Hello");          /* fits    */
    printf("Copied (fits):     \"%s\"\n", small);

    safe_strcpy(small, sizeof(small), "This string is way too long!"); /* truncated */
    printf("Copied (truncated): \"%s\"\n", small);

    /* --- Demo 2: sanitize_input ------------------------------------- */
    print_separator("sanitize_input");

    char clean1[] = "NodeA";
    sanitize_input(clean1, sizeof(clean1));

    char dirty1[] = "Node;A";           /* semicolon injection attempt */
    sanitize_input(dirty1, sizeof(dirty1));

    char dirty2[] = "rm -rf `evil`";    /* backtick command substitution */
    sanitize_input(dirty2, sizeof(dirty2));

    char dirty3[] = "A\x01\x7FB";       /* non-printable bytes */
    sanitize_input(dirty3, sizeof(dirty3));

    /* --- Demo 3: safe_int_parse ------------------------------------- */
    print_separator("safe_int_parse");

    long result;
    if (safe_int_parse("42", 0, 100, &result))
        printf("Parsed: %ld\n", result);

    safe_int_parse("999",  0, 100, &result);   /* out of range  */
    safe_int_parse("abc",  0, 100, &result);   /* non-numeric   */
    safe_int_parse("12x",  0, 100, &result);   /* trailing junk */

    /* --- Demo 4: safe_read (interactive) ---------------------------- */
    print_separator("safe_read (interactive)");

    char input[32];
    printf("Enter a label (max %zu chars): ", sizeof(input) - 1);
    fflush(stdout);

    int rc = safe_read(input, sizeof(input));
    if (rc == 1) {
        sanitize_input(input, sizeof(input));
        printf("Final clean value: \"%s\"\n", input);
    } else if (rc == -1) {
        printf("Input was too long and has been truncated.\n");
        sanitize_input(input, sizeof(input));
        printf("Final clean value: \"%s\"\n", input);
    } else {
        printf("No input received.\n");
    }

    return 0;
}
