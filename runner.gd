extends Autowork

func _ready():
    add_directory("res://tests")
    run_tests()
    get_tree().quit()
