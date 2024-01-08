/*
 * Emyzelium (Go)
 *
 * is another wrapper around ZeroMQ's Publish-Subscribe messaging pattern
 * with mandatory Curve security and optional ZAP authentication filter,
 * over Tor, through Tor SOCKS proxy,
 * for distributed artificial elife, decision making etc. systems where
 * each peer, identified by its public key, onion address, and port,
 * publishes and updates vectors of vectors of bytes of data
 * under unique topics that other peers can subscribe to
 * and receive the respective data.
 *
 * https://github.com/emyzelium/emyzelium-go
 *
 * emyzelium@protonmail.com
 *
 * Copyright (c) 2023-2024 Emyzelium caretakers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Demo
 */

package main

import (
	emz "github.com/emyzelium/emyzelium-go"
	tcell "github.com/gdamore/tcell/v2"

	crrand "crypto/rand"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	AlienSecretKey string = "gr6Y.04i(&Y27ju0g7m0HvhG0:rDmx<Y[FvH@*N("
	AlienPublicKey string = "iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R"
	AlienOnion     string = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" // from service_dir/hostname, without .onion
	AlienPort      uint16 = 60847

	JohnSecretKey string = "gbMF0ZKztI28i6}ax!&Yw/US<CCA9PLs.Osr3APc"
	JohnPublicKey string = "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW"
	JohnOnion     string = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" // from service_dir/hostname, without .onion
	JohnPort      uint16 = 60848

	MarySecretKey string = "7C*zh5+-8jOI[+^sh[dbVnW{}L!A&7*=j/a*h5!Y"
	MaryPublicKey string = "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0"
	MaryOnion     string = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" // from service_dir/hostname, without .onion
	MaryPort      uint16 = 60849

	defAutoemitInterval float64 = 4.0
	defFramerate        int     = 30
)

type Other struct {
	name      string
	publicKey string
}

type RealmCA struct {
	name             string
	efunguz          *emz.Efunguz
	height           int
	width            int
	cells            [][]uint8
	birth            map[int]bool
	survival         map[int]bool
	autoemitInterval float64
	framerate        int
	iTurn            uint64
	cursorY          int
	cursorX          int
	others           []Other
}

func timeMuSec() int64 {
	return time.Now().UnixMicro()
}

func printStr(scr tcell.Screen, y int, x int, s string, fc tcell.Color, bc tcell.Color) {
	style := tcell.StyleDefault.Background(bc).Foreground(fc)
	for _, r := range []rune(s) {
		scr.SetContent(x, y, r, nil, style)
		x++
	}
}

func printRect(scr tcell.Screen, y int, x int, h int, w int, fc tcell.Color, bc tcell.Color) {
	printStr(scr, y, x, "┌", fc, bc)
	printStr(scr, y, x+w-1, "┐", fc, bc)
	printStr(scr, y+h-1, x+w-1, "┘", fc, bc)
	printStr(scr, y+h-1, x, "└", fc, bc)
	for i := 1; i < (h - 1); i++ {
		printStr(scr, y+i, x, "│", fc, bc)
		printStr(scr, y+i, x+w-1, "│", fc, bc)
	}
	for j := 1; j < (w - 1); j++ {
		printStr(scr, y, x+j, "─", fc, bc)
		printStr(scr, y+h-1, x+j, "─", fc, bc)
	}
}

func printStrDef(scr tcell.Screen, y int, x int, s string) {
	printStr(scr, y, x, s, tcell.ColorLightGrey, tcell.ColorReset)
}

func printRectDef(scr tcell.Screen, y int, x int, h int, w int) {
	printRect(scr, y, x, h, w, tcell.ColorLightGrey, tcell.ColorReset)
}

func intset_to_str(set map[int]bool, do_sort bool) string {
	ints := make([]int, 0, len(set))
	for el := range set {
		ints = append(ints, el)
	}
	if do_sort {
		slices.Sort(ints)
	}
	str := "{"
	first := true
	for _, el := range ints {
		if first {
			first = false
		} else {
			str += ", "
		}
		str += fmt.Sprint(el)
	}
	return str + "}"
}

func (r *RealmCA) init(name string, secretkey string, whitelistPublicKeys map[string]bool, pub_port uint16, height int, width int, birth map[int]bool, survival map[int]bool, autoemitInterval float64, framerate int) {
	r.name = name
	r.efunguz = new(emz.Efunguz)
	r.efunguz.Init(secretkey, whitelistPublicKeys, pub_port, emz.DefTorProxyPort, emz.DefTorProxyHost)
	r.height = height
	r.width = width
	r.cells = make([][]uint8, height)
	for y := 0; y < height; y++ {
		r.cells[y] = make([]uint8, width)
	}
	r.birth = make(map[int]bool)
	for k := range birth {
		r.birth[k] = true
	}
	r.survival = make(map[int]bool)
	for k := range survival {
		r.survival[k] = true
	}
	r.autoemitInterval = autoemitInterval
	r.framerate = framerate
	r.cursorY = r.height >> 1
	r.cursorX = r.width >> 1
}

func (r *RealmCA) addOther(name string, publicKey string, onion string, port uint16) {
	if eh, err := r.efunguz.AddEhypha(publicKey, onion, port); err == nil {
		eh.AddEtale("")
		eh.AddEtale("zone")
	}
	r.others = append(r.others, Other{name, publicKey})
}

func (r *RealmCA) flip(y int, x int) {
	fY := r.cursorY
	if y >= 0 {
		fY = y
	}
	fX := r.cursorX
	if x >= 0 {
		fX = x
	}
	r.cells[fY][fX] ^= 1
}

func (r *RealmCA) clear() {
	for y := 0; y < r.height; y++ {
		for x := 0; x < r.width; x++ {
			r.cells[y][x] = 0
		}
	}
	r.iTurn = 0
}

func (r *RealmCA) reset() {
	b := make([]byte, 1)
	for y := 0; y < r.height; y++ {
		for x := 0; x < r.width; x++ {
			crrand.Read(b)
			r.cells[y][x] = b[0] & 1
		}
	}
	r.iTurn = 0
}

func (r *RealmCA) render(scr tcell.Screen, showCursor bool) {
	h := r.height
	w := r.width
	wTert := w / 3

	printRectDef(scr, 0, 0, (h>>1)+2, w+2)

	printStrDef(scr, 0, wTert, "┬┬")
	printStrDef(scr, 0, w-wTert, "┬┬")
	printStrDef(scr, 1+(h>>1), wTert, "┴┴")
	printStrDef(scr, 1+(h>>1), w-wTert, "┴┴")
	printStrDef(scr, 0, 2, "[ From others ]")
	printStrDef(scr, 0, 3+w-wTert, "[ To others ]")

	cellChars := [][]string{{" ", "▀"}, {"▄", "█"}}

	for i := 0; i < (h >> 1); i++ {
		y := i << 1
		rowStr := ""
		for x := 0; x < w; x++ {
			rowStr += cellChars[r.cells[y+1][x]&1][r.cells[y][x]&1]
		}
		printStr(scr, 1+i, 1, rowStr, tcell.ColorWhite, tcell.ColorReset) // white on black
	}

	statusStr := fmt.Sprintf("[ T = %d", r.iTurn)

	if showCursor {
		i := r.cursorY >> 1
		m := r.cursorY & 1
		cell_high := int(r.cells[i<<1][r.cursorX] & 1)
		cell_low := int(r.cells[(i<<1)+1][r.cursorX] & 1)

		chars := [][][]string{{{"▀", "▄"}, {"▀", "▀"}}, {{"▄", "▄"}, {"▄", "▀"}}}
		fclrs := [][][]tcell.Color{{{tcell.ColorDarkRed, tcell.ColorDarkRed}, {tcell.ColorBrown, tcell.ColorWhite}}, {{tcell.ColorWhite, tcell.ColorOrange}, {tcell.ColorWhite, tcell.ColorWhite}}}
		bclrs := [][][]tcell.Color{{{tcell.ColorReset, tcell.ColorReset}, {tcell.ColorReset, tcell.ColorDarkRed}}, {{tcell.ColorDarkRed, tcell.ColorReset}, {tcell.ColorOrange, tcell.ColorOrange}}}

		sChar := chars[cell_low][cell_high][m]
		sFclr := fclrs[cell_low][cell_high][m]
		sBclr := bclrs[cell_low][cell_high][m]

		printStr(scr, 1+i, 1+r.cursorX, sChar, sFclr, sBclr)

		statusStr += fmt.Sprintf(", X = %d, Y = %d, C = %d", r.cursorX, r.cursorY, r.cells[r.cursorY][r.cursorX]&1)
	}

	statusStr += " ]"
	printStrDef(scr, 1+(h>>1), 1+((w-len(statusStr))>>1), statusStr)
}

func (r *RealmCA) moveCursor(dY int, dX int) {
	r.cursorY = min(r.height-1, max(0, r.cursorY+dY))
	r.cursorX = min(r.width-1, max(0, r.cursorX+dX))
}

func (r *RealmCA) turn() {
	// Not much optimisation...
	h := r.height
	w := r.width
	// Count alive neighbors
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if (r.cells[y][x] & 1) != 0 { // increment number of neighbors for all neighboring cells
				for nY := y - 1; nY <= (y + 1); nY++ {
					if (nY >= 0) && (nY < h) {
						for nX := x - 1; nX <= (x + 1); nX++ {
							if ((nY != y) || nX != x) && (nX >= 0) && (nX < w) {
								r.cells[nY][nX] += 2 // accumulate in bits 1 and higher
							}
						}
					}
				}
			}
		}
	}
	// Update
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c, an := r.cells[y][x]&1, int(r.cells[y][x]>>1)
			if c == 1 {
				if !r.survival[an] {
					c = 0
				}
			} else {
				if r.birth[an] {
					c = 1
				}
			}
			r.cells[y][x] = c
		}
	}
	r.iTurn++
}

func (r *RealmCA) getPartsFromZone() [][]byte {
	var parts [][]byte
	h := r.height
	w := r.width
	zh := h
	zw := w / 3
	parts = append(parts, []byte{byte(zh & 0xFF), byte((zh >> 8) & 0xFF)})
	parts = append(parts, []byte{byte(zw & 0xFF), byte((zw >> 8) & 0xFF)})
	parts = append(parts, make([]byte, zh*zw))
	for y := 0; y < zh; y++ {
		for x := 0; x < zw; x++ {
			parts[2][y*zw+x] = r.cells[y][w-zw+x]
		}
	}
	return parts
}

func (r *RealmCA) putPartsToZone(parts [][]byte) {
	if len(parts) == 3 {
		if (len(parts[0]) == 2) && (len(parts[1]) == 2) {
			szh := int(parts[0][0]) + (int(parts[0][1]) << 8)
			szw := int(parts[1][0]) + (int(parts[1][1]) << 8)
			if len(parts[2]) == (szh * szw) {
				dzh := min(szh, r.height)
				dzw := min(szw, r.width/3)
				for y := 0; y < dzh; y++ {
					for x := 0; x < dzw; x++ {
						r.cells[y][x] = parts[2][y*szw+x] & 1
					}
				}

			}

		}
	}
}

func (r *RealmCA) emitEtales() {
	r.efunguz.EmitEtale("",
		[][]byte{[]byte("zone"), []byte("2B height (h), 2B width (w), h×wB zone by rows")})
	r.efunguz.EmitEtale("zone",
		r.getPartsFromZone())
}

func (r *RealmCA) updateEfunguz() {
	r.efunguz.Update()
}

func (r *RealmCA) run(scr tcell.Screen) {
	_, nRows := scr.Size()

	h := r.height

	quit := false
	paused := false
	render := true
	autoemit := true

	tStart := timeMuSec()

	var tLastRender float64 = -65536.0
	var tLastEmit float64 = -65536.0

	for !quit {
		t := 1e-6 * float64(timeMuSec()-tStart)

		if (t-tLastRender)*float64(r.framerate) > 1.0 {
			scr.Clear()

			if render {
				r.render(scr, paused)
			} else {
				printStrDef(scr, 0, 0, "Render OFF")
			}

			printStrDef(scr, (h>>1)+2, 0, fmt.Sprintf("This realm: \"%s's\" (birth: %s, survival: %s), SLE %.1f, autoemit (%.1f) %s, InConnsN %d", r.name, intset_to_str(r.birth, true), intset_to_str(r.survival, true), t-tLastEmit, r.autoemitInterval, map[bool]string{false: "OFF", true: "ON"}[autoemit], r.efunguz.InConnectionsNum()))
			othersStr := ""
			for i := 0; i < len(r.others); i++ {
				if i > 0 {
					othersStr += ", "
				}
				other := &r.others[i]
				othersStr += fmt.Sprintf("[%d] \"%s's\"", i+1, other.name)
				if eh, err := r.efunguz.GetEhypha(other.publicKey); err == nil {
					if et, err := eh.GetEtale("zone"); err == nil {
						othersStr += fmt.Sprintf(" (SLU %.1f)", t-1e-6*float64(et.TIn()-tStart))
					}
				}
			}
			printStrDef(scr, (h>>1)+3, 0, fmt.Sprintf("Other realms: %s", othersStr))

			printStrDef(scr, nRows-3, 0, "[Q] quit, [C] clear, [R] reset, [V] render on/off, [P] pause/resume")
			printStrDef(scr, nRows-2, 0, "[A] autoemit on/off, [E] emit, [1-9] import")
			printStrDef(scr, nRows-1, 0, "If paused: [T] turn, [→ ↑ ← ↓] move cursor, [ ] flip cell")

			scr.Show()

			tLastRender = t
		}

		if autoemit && (t-tLastEmit > r.autoemitInterval) {
			r.emitEtales()
			tLastEmit = t
		}

		r.updateEfunguz()

		if !paused {
			r.turn()
		}

		for scr.HasPendingEvent() {
			ev := scr.PollEvent()

			switch ev := ev.(type) {
			case *tcell.EventKey:
				if ev.Key() == tcell.KeyRune {
					rn := ev.Rune()
					switch rn {
					case 'q', 'Q':
						quit = true
					case 'c', 'C':
						r.clear()
					case 'r', 'R':
						r.reset()
					case 'v', 'V':
						render = !render
					case 'p', 'P':
						paused = !paused
					case 'a', 'A':
						autoemit = !autoemit
					case 'e', 'E':
						r.emitEtales()
						tLastEmit = t
					}
					if (rn >= '1') && (rn <= '9') {
						iOther := int(rn - '1')
						if iOther < len(r.others) {
							if eh, err := r.efunguz.GetEhypha(r.others[iOther].publicKey); err == nil {
								if et, err := eh.GetEtale("zone"); err == nil {
									r.putPartsToZone(et.Parts())
								}
							}
						}
					}
				}

				if paused {
					switch ev.Key() {
					case tcell.KeyRune:
						switch ev.Rune() {
						case 't', 'T':
							r.turn()
						case ' ':
							r.flip(-1, -1)
						}
					case tcell.KeyRight:
						r.moveCursor(0, 1)
					case tcell.KeyUp:
						r.moveCursor(-1, 0)
					case tcell.KeyLeft:
						r.moveCursor(0, -1)
					case tcell.KeyDown:
						r.moveCursor(1, 0)
					}
				}
			}
		}
	}

}

func (r *RealmCA) drop() {
	r.efunguz.Drop()
	r.efunguz = nil
}

func run_realm(name string) error {
	scr, err := tcell.NewScreen()
	if err != nil {
		return errors.New("Cannot make new screen")
	}

	defer func() {
		maybePanic := recover()
		scr.Fini()
		if maybePanic != nil {
			panic(maybePanic)
		}
	}()

	if err := scr.Init(); err != nil {
		return errors.New("Cannot init new screen")
	}

	defStyle := tcell.StyleDefault.Background(tcell.ColorReset).Foreground(tcell.ColorReset)
	scr.SetStyle(defStyle)

	var secretKey string
	var pubPort uint16
	var that1Name, that1PublicKey, that1Onion string
	var that1Port uint16
	var that2Name, that2PublicKey, that2Onion string
	var that2Port uint16
	var birth map[int]bool
	var survival map[int]bool

	switch strings.ToUpper(name) {
	case "ALIEN":
		secretKey = AlienSecretKey
		pubPort = AlienPort
		that1Name = "John"
		that1PublicKey = JohnPublicKey
		that1Onion = JohnOnion
		that1Port = JohnPort
		that2Name = "Mary"
		that2PublicKey = MaryPublicKey
		that2Onion = MaryOnion
		that2Port = MaryPort
		birth = map[int]bool{3: true, 4: true}
		survival = map[int]bool{3: true, 4: true} // 3-4 Life
	case "JOHN":
		secretKey = JohnSecretKey
		pubPort = JohnPort
		that1Name = "Alien"
		that1PublicKey = AlienPublicKey
		that1Onion = AlienOnion
		that1Port = AlienPort
		that2Name = "Mary"
		that2PublicKey = MaryPublicKey
		that2Onion = MaryOnion
		that2Port = MaryPort
		birth = map[int]bool{3: true}
		survival = map[int]bool{2: true, 3: true} // classic Conway's Life
	case "MARY":
		secretKey = MarySecretKey
		pubPort = MaryPort
		that1Name = "Alien"
		that1PublicKey = AlienPublicKey
		that1Onion = AlienOnion
		that1Port = AlienPort
		that2Name = "John"
		that2PublicKey = JohnPublicKey
		that2Onion = JohnOnion
		that2Port = JohnPort
		birth = map[int]bool{3: true}
		survival = map[int]bool{2: true, 3: true} // classic Conway's Life
	default:
		return errors.New(fmt.Sprintf("Unknown realm name: \"%s\". Must be \"Alien\", \"John\", or \"Mary\".", name))
	}

	nColumns, nRows := scr.Size()
	height := (nRows - 8) << 1 // even
	width := nColumns - 2

	var realm RealmCA
	realm.init(name, secretKey, map[string]bool{}, pubPort, height, width, birth, survival, defAutoemitInterval, defFramerate)

	// Uncomment to restrict: Alien gets data from John and Mary; John gets data from Alien but not from Mary; Mary gets data from neither Alien, nor John
	// realm.efunguz.AddWhitelistPublicKeys(map[string]bool{that1PublicKey: true})

	realm.addOther(that1Name, that1PublicKey, that1Onion, that1Port)
	realm.addOther(that2Name, that2PublicKey, that2Onion, that2Port)

	realm.reset()

	realm.run(scr)

	realm.drop()

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Syntax: demo <Alien|John|Mary>\n")
		return
	}
	if err := run_realm(os.Args[1]); err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
	return
}
