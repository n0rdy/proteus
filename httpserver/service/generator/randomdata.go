package generator

import "math/rand/v2"

type RandomDataGenerator struct {
}

var (
	hundredRandomWords = []string{
		"Mountain", "Basket", "Pencil", "Lantern", "Ribbon", "Bookshelf", "Bicycle", "Waterfall", "Candle", "Mirror",
		"Pillow", "Elephant", "Keyboard", "Kite", "Jacket", "Mango", "Brush", "Clock", "Ticket", "Ladder", "Bubble",
		"Sandal", "Notebook", "Whale", "Balloon", "Magnet", "Zebra", "Cupcake", "Telescope", "Turtle", "Blanket",
		"Parrot", "Helicopter", "Volcano", "Diary", "Chocolate", "Pineapple", "Sunglasses", "Apricot", "Chair",
		"Glue", "Statue", "Broom", "Necklace", "Pumpkin", "Train", "Iceberg", "Hammer", "Shoe", "Dolphin", "Drawer",
		"Lightbulb", "Key", "Tower", "Plate", "Robot", "Eagle", "Guitar", "Button", "Brush", "Castle", "Corn",
		"Scissors", "Sofa", "Rainbow", "Carrot", "Sheep", "Gate", "Envelope", "Owl", "Basket", "Spoon", "Walnut",
		"Cactus", "Shark", "Flag", "Map", "Jeans", "Lemon", "Pigeon", "Harp", "Cork", "Hat", "Bell", "Bicycle", "Axe",
		"Skirt", "Snail", "Firefly", "Peacock", "Vase", "Quilt", "Orange", "Fox", "Igloo", "Leaf", "Nail", "Tent",
		"Windmill", "Seashell",
	}
)

func (rdg *RandomDataGenerator) RandomString() string {
	return hundredRandomWords[rand.IntN(len(hundredRandomWords))]
}

func (rdg *RandomDataGenerator) RandomInt() int {
	return rand.Int()
}

func (rdg *RandomDataGenerator) RandomFloat() float64 {
	return rand.Float64()
}

func (rdg *RandomDataGenerator) RandomBool() bool {
	return rand.Int()%2 == 0
}
