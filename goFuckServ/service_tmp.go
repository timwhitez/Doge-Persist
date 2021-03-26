package main

import (
	"C"
	"log"
	"os"
	//"os/exec"
	"github.com/kardianos/service"
	"time"
)

//最终执行

type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	for {
		time.Sleep(time.Second)
		log.Println("running")
	}
}

func (p *program) Stop(s service.Service) error {
	return nil
}

func main() {
	svcConfig := &service.Config{
		Name:        "GoService",
		DisplayName: "GoService",
		Description: "windows service form golang",
		StartType:   "auto",
		//可选字段，用于指定服务的可执行文件。
		//如果为空，则使用当前可执行文件。
		Executable: "C:/windows/system32/cmd.exe",
		Arguments:  []string{"/c", "start", "C:/windows/system32/calc.exe"},
	}

	argLen := len(os.Args)
	if argLen < 3 {
		log.Fatalln("not enough argument...")
	}
	if os.Args[1] == "start" && argLen < 4 {
		log.Fatalln("not enough argument...")
	}

	svcConfig.Name = os.Args[2]
	svcConfig.DisplayName = os.Args[2]

	if argLen >= 4 {
		svcConfig.Arguments[2] = os.Args[3]
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if os.Args[1] == "start" {
		err = s.Install()
		if err != nil {
			log.Printf("service install failed...")
			return
		}
		s.Start()
		//log.Println("Service Start")
		return
	}

	if os.Args[1] == "stop" {
		s.Stop()
		s.Uninstall()
		//log.Println("Service Stop")
		return
	}

	if err = s.Run(); err != nil {
		log.Fatal(err)
	}
}
