#from tkinter import *
#import tkinter as tk
#from tkinter import messagebox
from GUI import app_gui as app

#from ImageLoader import ImageLoader as il
#from AES import aes_enc

#def performTest():
#    messagebox.showinfo("Hash generation", "Image hashing done")

frame = app.App()
frame.run()

#mainRoot = tk.Tk()

#2 framy na kazdy image loader
#leftFrame = Frame(mainRoot, width=250, height=250)
#leftFrame.pack(side=TOP)

#rightFrame = Frame(mainRoot, width=250, height=250)
#rightFrame.pack(side=TOP)

#image loader pre kazdy obrazok
#loader = il.ImageLoader(leftFrame)
#loader2 = il.ImageLoader(rightFrame)


#button s vyvolanim message boxu
#actionButton = Button(mainRoot, text="Perform test", command=performTest)
#actionButton.pack(side=BOTTOM)

#mainRoot.mainloop()

