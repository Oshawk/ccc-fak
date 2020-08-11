Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provision "shell", path: "vagrant.sh"
  config.vm.synced_folder ".", "/fak"
end
