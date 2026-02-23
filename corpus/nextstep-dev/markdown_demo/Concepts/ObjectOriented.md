---
title: "Object-Oriented Programming in NeXTSTEP"
source: "index.html"
format: "HTML"
section: "Concepts"
converted: "2025-11-09"
---

# Object-Oriented Programming

NeXTSTEP is built on a foundation of object-oriented programming (OOP). This chapter introduces the key concepts of OOP as implemented in the NeXTSTEP development environment.

## Introduction

Object-oriented programming organizes software design around data, or **objects** , rather than functions and logic. An object can be defined as a data field that has unique attributes and behavior.

## Key Principles

### Encapsulation

Encapsulation is the bundling of data with the methods that operate on that data. It restricts direct access to some of an object's components.

```objc @interface BankAccount : NSObject { @private double balance; } \- (void)deposit:(double)amount; \- (void)withdraw:(double)amount; \- (double)balance; @end ``` 

### Inheritance

Inheritance enables new objects to take on the properties of existing objects. A class that is used as the basis for inheritance is called a superclass or base class.

```objc @interface CheckingAccount : BankAccount { double overdraftLimit; } \- (void)setOverdraftLimit:(double)limit; @end ``` 

### Polymorphism

Polymorphism allows objects of different types to be accessed through the same interface. Each type can provide its own independent implementation of this interface.

## The NeXTSTEP Class Hierarchy

All NeXTSTEP classes inherit from `NSObject`, which provides:

  * Memory management
  * Runtime introspection
  * Object comparison
  * Archiving support



## Further Reading

See also:

  * [Dynamic Loading](../../DynamicLoading.md/index.md)
  * [Foundation Framework Reference](../../GeneralRef/Foundation/index.md)
  * [Memory Management](../../ProgrammingTopics/MemoryManagement.md/index.md)


