
from abc import ABC, abstractmethod


class Student:
    def __init__(self, student_id, name, gpa):
        self.student_id = student_id
        self.name = name
        self.gpa = gpa

    def __str__(self):
        return f"ID: {self.student_id} | Name: {self.name} | GPA: {self.gpa}"


class SortStrategy(ABC):
    @abstractmethod
    def sort(self, students):
        pass


class SortByGpaAscending(SortStrategy):
    def sort(self, students):
        return sorted(students, key=lambda s: s.gpa)


class SortByGpaDescending(SortStrategy):
    def sort(self, students):
        return sorted(students, key=lambda s: s.gpa, reverse=True)


class SortByName(SortStrategy):
    def sort(self, students):
        return sorted(students, key=lambda s: s.name.lower())


class StudentManager:
    def __init__(self):
        self.students = []
        self.sort_strategy = None

    def add_student(self, student):
        self.students.append(student)

    def set_sort_strategy(self, strategy):
        self.sort_strategy = strategy

    def display_students(self):
        for student in self.students:
            print(student)

    def sort_students(self):
        if self.sort_strategy is None:
            print("Vui long chon chien luoc sap xep.")
            return

        sorted_students = self.sort_strategy.sort(self.students)

        for student in sorted_students:
            print(student)


def main():
    manager = StudentManager()

    manager.add_student(Student("SV01", "Nguyen Van An", 3.2))
    manager.add_student(Student("SV02", "Tran Thi Binh", 3.8))
    manager.add_student(Student("SV03", "Le Van Cuong", 2.9))

    print("=== Sap xep GPA tang dan ===")
    manager.set_sort_strategy(SortByGpaAscending())
    manager.sort_students()

    print("\n=== Sap xep GPA giam dan ===")
    manager.set_sort_strategy(SortByGpaDescending())
    manager.sort_students()

    print("\n=== Sap xep theo ten ===")
    manager.set_sort_strategy(SortByName())
    manager.sort_students()


if __name__ == "__main__":
    main()
