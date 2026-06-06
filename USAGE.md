# 🎯 Usage Guide - ShadowProtocol v3.0

## Interactive Mode

### Starting the Application

```bash
shadowprotocol
```

Or:
```bash
python3 -m shadowprotocol
./run.sh
```

### Main Menu Options

```
╔ ShadowProtocol v3.0 | Mode: IDLE | Ready ═════════════════╗
───────────────────────────────────────────────────────────────
 ▶ LIVE OUTPUT
───────────────────────────────────────────────────────────────
 [*] === ShadowProtocol v3.0 - Fusion TUI + Radare2 ===
 [*] Appuyez sur [1] pour sélectionner une cible
 [*] Appuyez sur [a], [b], ou [c] pour lancer les modes
 [*] Appuyez sur [q] à tout moment pour arrêter proprement
───────────────────────────────────────────────────────────────
 [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%
 [q] Quitter | Modes: [a] [b] [c]
```

### Available Commands

| Key | Action |
|-----|--------|
| `1` | Select target .so file |
| `a` | Start MODE A (Manual) |
| `b` | Start MODE B (Auto) |
| `c` | Start MODE C (Raw r2) |
| `q` | Quit application |
| `Ctrl+C` | Force quit (clean shutdown) |

---

## Step-by-Step Workflow

### Step 1: Select Target

Press `[1]` to select a target .so file:

```
[*] Recherche des fichiers .so...
[*] 3 cible(s) détectée(s)
[1] /system/lib64/libc.so
    Arch: ARM64 | RW: ✓ | Size: 1.45MB
[2] /system/lib64/libm.so
    Arch: ARM64 | RW: ✗ | Size: 0.89MB
[3] /custom/lib/libapp.so
    Arch: ARM64 | RW: ✓ | Size: 2.34MB

Select target [1-3]: 3
[+] Cible sélectionnée: /custom/lib/libapp.so (ARM64)
```

### Step 2: Choose Mode

After selecting a target, choose a mode:

#### MODE A - Manual Patching

Press `[a]` for manual offset-based patching:

```
[*] Lancement MODE A...
[*] MODE A: Analyse manuelle démarrée...
[*] [A] Initialisation système...
[*] [A] Chargement binaire...
[*] [A] Analyse en-tête ELF...
[*] [A] Extraction symboles...
[*] [A] Vérification offset...
[*] [A] Validation pattern...
[+] Patch appliqué et vérifié
[+] MODE A: Analyse complétée avec succès
```

**Use when:**
- You have a specific offset from PPTool
- You want precise, manual control
- Testing specific locations

#### MODE B - Automatic Patching

Press `[b]` for full binary scan and auto patching:

```
[*] Lancement MODE B...
[*] MODE B: Scan automatique démarré...
[*] [B] Initialisation scanner...
[*] [B] Chargement complet binaire...
[*] [B] Scan .text section...
[*] [B] Détection pattern 1...
[*] [B] Détection pattern 2...
[*] [B] Détection pattern 3...
[*] [*] 15/42 patchés
[*] [*] 30/42 patchés
[*] [*] 42/42 patches appliqués
[+] MODE B: Scan et patches complétés
```

**Use when:**
- You want to patch all occurrences automatically
- No offset information available
- Batch patching multiple locations

#### MODE C - Raw Radare2

Press `[c]` for interactive Radare2 shell:

```
[*] Lancement MODE C...
[*] MODE C: Shell Radare2 démarré...
[*] [C] Initialisation r2...
[*] [C] Ouverture binaire en write...
[*] [C] Analyse basique (aaa)...

r2> aaa
[*] Analyzing function calls.
[*] finding function preludes
[*] Pre-computing function metadata.

r2> pd @ 0x1234
    0x00001234  add x0, x22, 0x30     ; Pattern to patch
    0x00001238  mov x1, x0
    0x0000123c  ret

r2> wa "add x0, x22, 0x20" @ 0x1234
[+] Patch appliqué et vérifié

r2> q
[+] MODE C: Manipulation Radare2 complétée
```

**Use when:**
- You need direct Radare2 command access
- Complex binary analysis required
- Custom patching logic

### Step 3: Monitor Progress

The progress bar shows real-time updates:

```
[████████████████░░░░░░░░░░░░░░░░░░░░] 60% MODE A 8/14
```

- Filled bars = completed steps
- Empty bars = remaining steps
- Percentage = overall progress
- "MODE A 8/14" = step counter

### Step 4: Completion

When mode finishes:

```
[+] MODE A: Analyse complétée avec succès
```

The UI returns to IDLE state, ready for next operation.

---

## Advanced Usage

### Using Offsets (MODE A)

If you have an offset from PPTool:

1. Start MODE A
2. The application will:
   - Seek to the offset
   - Validate the pattern `add x0, x22, 0x30` exists
   - Replace with `add x0, x22, 0x20`
   - Verify the patch

Example offset: `0x1234abc0`

### Batch Patching (MODE B)

MODE B automatically:
1. Scans entire binary
2. Finds ALL occurrences of pattern
3. Displays count and locations
4. Patches each one
5. Verifies each patch
6. Shows statistics

### Custom Radare2 Commands (MODE C)

You can run any r2 command:

```
r2> aaa              # Analyze all functions
r2> pd @ 0x1234      # Disassemble
r2> wa "mov x0, 1"   # Write assembly
r2> s 0x5000         # Seek
r2> df               # List functions
r2> is               # List imports
r2> pI 2             # Hex dump
r2> quit or q        # Exit
```

---

## Tips & Tricks

### 1. Terminal Too Small?
Application automatically adapts to terminal size. Resize and it updates automatically.

### 2. Missing Dependencies
If errors occur:
```bash
sudo apt install radare2
pip install r2pipe>=1.6.0
```

### 3. Verify Patch Success
Check logs for `[+] Patch appliqué et vérifié`

### 4. Multiple Binaries
Repeat Step 1 to select different .so files

### 5. Logging Output
All output is logged with timestamps:
```
[10:25:32] [*] MODE A: Analyse démarrée...
[10:25:33] [+] Cible sélectionnée...
```

### 6. Error Recovery
Press `q` at any time to stop gracefully
- Running modes get notified to stop
- Waits up to 5 seconds for cleanup
- Terminal restored to normal state

### 7. Background Mode (Scripting)
For automation:
```bash
python3 -m shadowprotocol A  # Run MODE A directly
python3 -m shadowprotocol B  # Run MODE B directly
```

---

## Keyboard Controls

| Key | Mode | Action |
|-----|------|--------|
| `1` | Any | Select target |
| `a` | IDLE | Start MODE A |
| `b` | IDLE | Start MODE B |
| `c` | IDLE | Start MODE C |
| `q` | Any | Graceful quit |
| `Ctrl+C` | Any | Force quit |

---

## Log Levels

| Prefix | Color | Meaning |
|--------|-------|---------|
| `[*]` | Cyan | Information |
| `[+]` | Green | Success |
| `[!]` | Red | Error |
| `[W]` | Yellow | Warning |
| `[D]` | Dim Yellow | Debug |

---

## Performance

| Operation | Time |
|-----------|------|
| Startup | ~0.5s |
| Target selection | ~1-2s |
| MODE A execution | ~3-5s |
| MODE B execution | ~5-15s (varies by binary size) |
| MODE C initialization | ~2s |

---

## Troubleshooting

### UI doesn't display properly
- Make sure terminal size is at least 80x24
- Set `TERM=xterm-256color`
- Falls back to ANSI if curses fails

### Mode hangs
- Press `q` or `Ctrl+C`
- Will wait max 5 seconds before force quit
- Check Radare2 is properly installed

### Offset validation fails
- Verify offset format: must start with `0x`
- Check offset exists in binary
- Use MODE C to explore binary first

### Permission denied on .so file
- Make sure file is readable
- For patching, make file writable:
  ```bash
  chmod +w /path/to/lib.so
  ```

---

## Safety Notes

✅ **Always backup binary before patching**

```bash
cp /path/to/lib.so /path/to/lib.so.backup
```

✅ **Test on copy first**

```bash
cp lib.so lib.so.test
# Run modes on lib.so.test
# If successful, apply to real file
```

✅ **Verify patches**

Check logs confirm `[+] Patch appliqué et vérifié`

---

## Examples

### Example 1: Patch Single Offset

```bash
$ shadowprotocol
[1] Select target
  → Choose /system/lib64/libapp.so
[a] MODE A
  → Enter offset: 0x12345678
  → Confirm: y
[+] Patch appliqué et vérifié
[q] Quit
```

### Example 2: Auto-Patch Binary

```bash
$ shadowprotocol
[1] Select target
  → Choose /custom/lib/lib.so
[b] MODE B
  → Scan automatically
  → Found 42 targets
  → Patch all? y
  → [+] 42/42 patches appliqués
[q] Quit
```

### Example 3: Explore Binary

```bash
$ shadowprotocol
[1] Select target
  → Choose library
[c] MODE C
  r2> aaa
  r2> pd @ 0x1000
  r2> s 0x5000
  r2> pdf
  r2> q
[q] Quit
```

---

**Usage Guide v3.0**  
Complete and up to date
