#Divya Patel ECE 56401- Computer Security - Final Project
#Custom exception classes for steganography error handling

class StegoError(Exception): pass
class StegoCapacityError(StegoError): pass
class InvalidImageError(StegoError): pass
class ExtractionError(StegoError): pass
