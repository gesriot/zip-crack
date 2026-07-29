// Password Cracker — native macOS/desktop GUI (Fyne), pure Go backends.
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"image/color"
	"strconv"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	nativedialog "github.com/sqweek/dialog"

	"zip_crack/crack"
)

//go:embed icon.png
var iconPNG []byte

func main() {
	appIcon := fyne.NewStaticResource("icon.png", iconPNG)

	a := app.NewWithID("com.passwordcracker.app")
	a.SetIcon(appIcon)
	// Always light: ignore system dark mode (softTheme forces VariantLight).
	a.Settings().SetTheme(&forcedLightTheme{})
	w := a.NewWindow("Password Cracker")
	w.SetIcon(appIcon)
	w.Resize(fyne.NewSize(560, 620))
	w.SetFixedSize(false)

	ui := newUI(w)
	w.SetContent(ui.root)
	w.ShowAndRun()
}

type ui struct {
	win fyne.Window

	pathLabel   *widget.Label
	typeLabel   *widget.Label
	warnLabel   *widget.Label
	statusLabel *widget.Label
	passLabel   *widget.Label
	statsLabel  *widget.Label
	charsetLab  *widget.Label
	combosLab   *widget.Label

	cbDigits  *widget.Check
	cbLower   *widget.Check
	cbUpper   *widget.Check
	cbSymbols *widget.Check
	minEntry  *widget.Entry
	maxEntry  *widget.Entry

	btnPick   *widget.Button
	btnCrack  *widget.Button
	btnCancel *widget.Button
	btnCopy   *widget.Button
	progress  *widget.ProgressBarInfinite

	info     *crack.ArchiveInfo
	cancelFn context.CancelFunc
	running  atomic.Bool
	password string

	root fyne.CanvasObject
}

func newUI(win fyne.Window) *ui {
	u := &ui{win: win}

	u.pathLabel = widget.NewLabel("Файл не выбран")
	u.pathLabel.Wrapping = fyne.TextWrapWord
	u.typeLabel = widget.NewLabel("")
	u.warnLabel = widget.NewLabel("")
	u.warnLabel.Wrapping = fyne.TextWrapWord
	u.statusLabel = widget.NewLabel("Выберите архив и настройте словарь")
	u.statusLabel.Wrapping = fyne.TextWrapWord
	u.passLabel = widget.NewLabel("")
	u.passLabel.TextStyle = fyne.TextStyle{Monospace: true}
	u.passLabel.Hide()
	u.statsLabel = widget.NewLabel("")
	u.charsetLab = widget.NewLabel("")
	u.charsetLab.TextStyle = fyne.TextStyle{Monospace: true}
	u.combosLab = widget.NewLabel("")

	// Entries first: Check.SetChecked fires OnChanged immediately, and
	// refreshCombos/dict read minEntry/maxEntry — must not be nil.
	u.minEntry = widget.NewEntry()
	u.minEntry.SetText("1")
	u.maxEntry = widget.NewEntry()
	u.maxEntry.SetText("4")

	u.cbDigits = widget.NewCheck("Цифры 0–9", nil)
	u.cbLower = widget.NewCheck("Латиница a–z", nil)
	u.cbUpper = widget.NewCheck("Латиница A–Z", nil)
	u.cbSymbols = widget.NewCheck("Прочие символы  !@#$…", nil)
	u.cbDigits.SetChecked(true)

	onDict := func(_ bool) { u.refreshCombos() }
	u.cbDigits.OnChanged = onDict
	u.cbLower.OnChanged = onDict
	u.cbUpper.OnChanged = onDict
	u.cbSymbols.OnChanged = onDict
	u.minEntry.OnChanged = func(string) { u.refreshCombos() }
	u.maxEntry.OnChanged = func(string) { u.refreshCombos() }

	u.progress = widget.NewProgressBarInfinite()
	u.progress.Hide()

	u.btnPick = widget.NewButton("Выбрать файл…", u.pickFile)
	u.btnCrack = widget.NewButton("Подобрать", u.startCrack)
	u.btnCancel = widget.NewButton("Отмена", u.cancelCrack)
	u.btnCancel.Disable()
	u.btnCopy = widget.NewButton("Копировать пароль", u.copyPassword)
	u.btnCopy.Hide()

	lenRow := container.NewHBox(
		widget.NewLabel("Длина от"),
		container.NewGridWrap(fyne.NewSize(64, 36), u.minEntry),
		widget.NewLabel("до"),
		container.NewGridWrap(fyne.NewSize(64, 36), u.maxEntry),
	)

	dictCard := widget.NewCard("Словарь (алфавит)", "", container.NewVBox(
		u.cbDigits, u.cbLower, u.cbUpper, u.cbSymbols,
		lenRow,
		u.charsetLab,
		u.combosLab,
	))

	buttons := container.NewGridWithColumns(3, u.btnPick, u.btnCrack, u.btnCancel)

	footer := widget.NewLabel(
		"Автовыбор: ZIP ZipCrypto → native; ZIP AES → yeka/zip; 7z → sevenzip; " +
			"encrypted DOCX/XLSX → MS-OFFCRYPTO (Word не нужен).",
	)
	footer.Wrapping = fyne.TextWrapWord

	u.root = container.NewVBox(
		u.pathLabel,
		u.typeLabel,
		u.warnLabel,
		buttons,
		dictCard,
		u.progress,
		u.statusLabel,
		u.passLabel,
		u.btnCopy,
		u.statsLabel,
		layout.NewSpacer(),
		footer,
	)

	u.refreshCombos()
	return u
}

func (u *ui) dict() crack.Dict {
	if u.minEntry == nil || u.maxEntry == nil {
		return crack.DefaultDict()
	}
	minL, _ := strconv.Atoi(u.minEntry.Text)
	maxL, _ := strconv.Atoi(u.maxEntry.Text)
	if minL < 1 {
		minL = 1
	}
	if maxL < 1 {
		maxL = 1
	}
	if minL > 64 {
		minL = 64
	}
	if maxL > 64 {
		maxL = 64
	}
	if minL > maxL {
		maxL = minL
	}
	return crack.Dict{
		UseDigits:     u.cbDigits.Checked,
		UseLatinLower: u.cbLower.Checked,
		UseLatinUpper: u.cbUpper.Checked,
		UseSymbols:    u.cbSymbols.Checked,
		MinLen:        minL,
		MaxLen:        maxL,
	}
}

func (u *ui) refreshCombos() {
	if u.charsetLab == nil || u.combosLab == nil {
		return
	}
	d := u.dict()
	cs := d.Charset()
	if cs == "" {
		u.charsetLab.SetText("(алфавит пуст)")
	} else {
		u.charsetLab.SetText(fmt.Sprintf("Символов: %d  ·  %s", len(cs), cs))
	}
	n, err := d.CombinationCount()
	slow := u.info != nil && u.info.SlowPath
	switch {
	case err != nil:
		u.combosLab.SetText("Комбинаций: слишком много (переполнение)")
	case n == 0:
		u.combosLab.SetText("Комбинаций: 0")
	case n > crack.MaxCombinations:
		u.combosLab.SetText(fmt.Sprintf("Комбинаций: %d – слишком много (лимит %d)", n, crack.MaxCombinations))
	case n > crack.WarnCombinations:
		u.combosLab.SetText(fmt.Sprintf("Комбинаций: %d – может занять много времени", n))
	case slow && n > 10_000:
		u.combosLab.SetText(fmt.Sprintf("Комбинаций: %d – AES/Office может занять заметное время", n))
	default:
		u.combosLab.SetText(fmt.Sprintf("Комбинаций: %d", n))
	}
}

func (u *ui) setControlsEnabled(on bool) {
	if on {
		u.btnPick.Enable()
		u.btnCrack.Enable()
		u.cbDigits.Enable()
		u.cbLower.Enable()
		u.cbUpper.Enable()
		u.cbSymbols.Enable()
		u.minEntry.Enable()
		u.maxEntry.Enable()
	} else {
		u.btnPick.Disable()
		u.btnCrack.Disable()
		u.cbDigits.Disable()
		u.cbLower.Disable()
		u.cbUpper.Disable()
		u.cbSymbols.Disable()
		u.minEntry.Disable()
		u.maxEntry.Disable()
	}
}

func (u *ui) pickFile() {
	if u.running.Load() {
		return
	}
	// Native OS dialog (NSOpenPanel on macOS). Fyne's own ShowFileOpen is
	// custom-drawn and does not use the system picker on Darwin.
	// Modal Cocoa dialogs must run on the UI thread (button handler is fine).
	path, err := nativedialog.File().
		Title("Выбрать архив или Office-файл").
		Filter("Архивы и Office", "zip", "7z", "zipx", "rar", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "doc", "xls", "ppt").
		Filter("Все файлы", "*").
		Load()
	if err != nil {
		if errors.Is(err, nativedialog.ErrCancelled) {
			return
		}
		u.statusLabel.SetText("Диалог: " + err.Error())
		return
	}
	if path == "" {
		return
	}
	u.loadPath(path)
}

func (u *ui) loadPath(path string) {
	u.password = ""
	u.passLabel.Hide()
	u.btnCopy.Hide()
	u.statsLabel.SetText("")
	u.pathLabel.SetText(path)
	u.statusLabel.SetText("Анализ архива…")

	info, err := crack.Probe(path)
	if err != nil {
		u.info = nil
		u.typeLabel.SetText("")
		u.warnLabel.SetText("")
		u.statusLabel.SetText(err.Error())
		return
	}
	u.info = info
	u.typeLabel.SetText(fmt.Sprintf("Тип: %s · движок: %s", info.TypeLabel, info.Backend))
	if info.Warning != "" {
		u.warnLabel.SetText(info.Warning)
	} else {
		u.warnLabel.SetText("")
	}
	u.statusLabel.SetText("Архив выбран. Нажмите «Подобрать».")
	u.refreshCombos()
}

func (u *ui) startCrack() {
	if u.running.Load() {
		return
	}
	if u.info == nil {
		u.statusLabel.SetText("Сначала выберите архив (кнопка «Выбрать файл…»)")
		return
	}
	d := u.dict()
	if d.Charset() == "" {
		u.statusLabel.SetText("Выберите хотя бы один набор символов")
		return
	}
	n, err := d.CombinationCount()
	if err != nil || n == 0 {
		u.statusLabel.SetText("Нет комбинаций для перебора")
		return
	}
	if n > crack.MaxCombinations {
		u.statusLabel.SetText(fmt.Sprintf(
			"Слишком много комбинаций (%d). Уменьшите длину или алфавит (лимит %d).",
			n, crack.MaxCombinations))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	u.cancelFn = cancel
	u.running.Store(true)
	u.setControlsEnabled(false)
	u.btnCancel.Enable()
	u.progress.Show()
	u.progress.Start()
	u.passLabel.Hide()
	u.btnCopy.Hide()
	u.statsLabel.SetText("")
	u.statusLabel.SetText("Идёт подбор…")
	u.password = ""

	info := u.info
	workers := crack.WorkersFor(info.Backend)

	go func() {
		res, err := crack.Crack(ctx, info.Tester, d, workers, func(tried uint64) {
			fyne.Do(func() {
				if u.running.Load() {
					u.statusLabel.SetText(fmt.Sprintf("Идёт подбор… проверено %d", tried))
				}
			})
		})
		fyne.Do(func() {
			u.finishRun()
			if err != nil {
				u.statusLabel.SetText(err.Error())
				return
			}
			switch {
			case res.Found:
				u.password = res.Password
				u.statusLabel.SetText("Пароль найден: " + res.Password)
				u.passLabel.SetText("Пароль: " + res.Password)
				u.passLabel.Show()
				u.btnCopy.Show()
			case res.Cancelled:
				u.statusLabel.SetText(fmt.Sprintf("Отменено (проверено %d вариантов)", res.Tried))
			default:
				u.statusLabel.SetText(fmt.Sprintf("Пароль не найден (проверено %d вариантов)", res.Tried))
			}
			u.statsLabel.SetText(fmt.Sprintf(
				"Время: %.3f с · проверено: %d · воркеров: %d",
				res.Elapsed.Seconds(), res.Tried, workers,
			))
		})
	}()
}

func (u *ui) cancelCrack() {
	if !u.running.Load() {
		return
	}
	u.statusLabel.SetText("Отмена…")
	if u.cancelFn != nil {
		u.cancelFn()
	}
	u.btnCancel.Disable()
}

func (u *ui) finishRun() {
	u.running.Store(false)
	u.cancelFn = nil
	u.progress.Stop()
	u.progress.Hide()
	u.btnCancel.Disable()
	u.setControlsEnabled(true)
}

func (u *ui) copyPassword() {
	if u.password == "" {
		return
	}
	u.win.Clipboard().SetContent(u.password)
	u.statusLabel.SetText("Пароль скопирован")
}

// forcedLightTheme always uses the light palette, ignoring system dark mode.
// theme.DefaultTheme() follows OS preference; we pin VariantLight for every color.
type forcedLightTheme struct{}

func (t *forcedLightTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	// Soft light accents on top of Fyne's light palette.
	switch n {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0xF4, G: 0xF5, B: 0xF2, A: 0xFF}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0x1F, G: 0x29, B: 0x33, A: 0xFF}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0xE8, G: 0xEC, B: 0xF0, A: 0xFF}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0xD5, G: 0xDA, B: 0xE0, A: 0xFF}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x9A, G: 0xA3, B: 0xAB, A: 0xFF}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x65, G: 0x71, B: 0x7C, A: 0xFF}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0xCF, G: 0xD6, B: 0xDD, A: 0xFF}
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x33}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x2F, G: 0x6F, B: 0xED, A: 0xFF}
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x12}
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0x2F, G: 0x6F, B: 0xED, A: 0x44}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x2F, G: 0x6F, B: 0xED, A: 0x33}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0xCF, G: 0xD6, B: 0xDD, A: 0xFF}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x33}
	case theme.ColorNameError:
		return color.NRGBA{R: 0xDC, G: 0x50, B: 0x50, A: 0xFF}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0x1B, G: 0x7F, B: 0x3A, A: 0xFF}
	case theme.ColorNameWarning:
		return color.NRGBA{R: 0xDC, G: 0x9A, B: 0x28, A: 0xFF}
	default:
		// Fall back to built-in light palette for any remaining tokens.
		return theme.LightTheme().Color(n, theme.VariantLight)
	}
}

func (t *forcedLightTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.LightTheme().Font(style)
}

func (t *forcedLightTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.LightTheme().Icon(n)
}

func (t *forcedLightTheme) Size(n fyne.ThemeSizeName) float32 {
	return theme.LightTheme().Size(n)
}
