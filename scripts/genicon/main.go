// genicon renders the NaviScope app icon set source (1024px PNG) using the
// same compass mark as the console favicon. Build tool only; not shipped.
package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
)

func main() {
	const size = 1024
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	blue := color.RGBA{R: 22, G: 27, B: 34, A: 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{blue}, image.Point{}, draw.Src)
	accent := color.RGBA{R: 86, G: 156, B: 214, A: 255}
	white := color.RGBA{R: 235, G: 241, B: 245, A: 255}
	// Outer hexagon-ish compass ring.
	fillPoly(img, regular(512, 512, 380, 6, 0), accent)
	fillPoly(img, regular(512, 512, 320, 6, 0), blue)
	// Needle: two triangles pointing up-right and down-left.
	fillPoly(img, []image.Point{{512, 232}, {652, 652}, {512, 560}}, white)
	fillPoly(img, []image.Point{{512, 560}, {372, 652}, {512, 792}}, white)
	out, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	if err := png.Encode(out, img); err != nil {
		panic(err)
	}
}

func regular(cx, cy, r int, n int, rot int) []image.Point {
	pts := make([]image.Point, n)
	for i := range n {
		angle := float64(rot) + float64(i)*360.0/float64(n)
		rad := angle * math.Pi / 180
		pts[i] = image.Point{cx + int(float64(r)*math.Sin(rad)), cy + int(float64(r)*math.Cos(rad))}
	}
	return pts
}

func fillPoly(img *image.RGBA, pts []image.Point, c color.Color) {
	minY, maxY := pts[0].Y, pts[0].Y
	for _, p := range pts {
		if p.Y < minY {
			minY = p.Y
		}
		if p.Y > maxY {
			maxY = p.Y
		}
	}
	for y := minY; y <= maxY; y++ {
		var xs []int
		for i := range pts {
			a, b := pts[i], pts[(i+1)%len(pts)]
			if (a.Y <= y && b.Y > y) || (b.Y <= y && a.Y > y) {
				xs = append(xs, a.X+(y-a.Y)*(b.X-a.X)/(b.Y-a.Y))
			}
		}
		for i := 0; i+1 < len(xs); i += 2 {
			for x := xs[i]; x <= xs[i+1]; x++ {
				img.Set(x, y, c)
			}
		}
	}
}
