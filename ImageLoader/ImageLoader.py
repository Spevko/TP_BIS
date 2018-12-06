from tkinter import *
from tkinter import filedialog
from PIL import Image, ImageTk


class ImageLoader:

    def __init__(self, root):
        self.LoadImageButton = Button(root,text = "Load image", command=self.LoadImage)
        self.LoadImageButton.pack(side = BOTTOM)
        self.OwnerRoot = root

    def LoadImage(self):
        imagePath = filedialog.askopenfilename()
        self.AddedImage = ImageTk.PhotoImage(Image.open(imagePath), width = 100, height = 100)
        self.ImageLabel = Label(self.OwnerRoot,image=self.AddedImage)
        self.ImageLabel.pack(side = TOP)



