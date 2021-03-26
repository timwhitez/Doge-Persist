package main

import (
	"C"
	"fmt"
	"log"
	"os"
	//"os/exec"
	"errors"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ConsoleLogger logs to the std err.
	ConsoleLogger  = consoleLogger{}
	system         System
	systemRegistry []System
	// ErrNameFieldRequired is returned when Config.Name is empty.
	ErrNameFieldRequired = errors.New("Config.Name field is required.")
	// ErrNoServiceSystemDetected is returned when no system was detected.
	ErrNoServiceSystemDetected = errors.New("No service system detected.")
	// ErrNotInstalled is returned when the service is not installed
	ErrNotInstalled = errors.New("the service is not installed")
	// ControlAction列出要在Control中使用的有效字符串文本
	ControlAction = [5]string{"start", "stop", "restart", "install", "uninstall"}
	interactive   = false
)

func (c *Config) execPath() (string, error) {
	if len(c.Executable) != 0 {
		return filepath.Abs(c.Executable)
	}
	return os.Executable()
}

type consoleLogger struct {
	info, warn, err *log.Logger
}

func init() {
	ConsoleLogger.info = log.New(os.Stderr, "I: ", log.Ltime)
	ConsoleLogger.warn = log.New(os.Stderr, "W: ", log.Ltime)
	ConsoleLogger.err = log.New(os.Stderr, "E: ", log.Ltime)
	ChooseSystem(windowsSystem{})
	var err error
	interactive, err = svc.IsAnInteractiveSession()
	if err != nil {
		panic(err)
	}

	//f, err := os.Create("C:/Windows/Temp/gowin.txt")
	if err != nil {
		log.Fatal(err)
	}
	//log.SetOutput(f)
}

func (c consoleLogger) Error(v ...interface{}) error {
	c.err.Print(v...)
	return nil
}
func (c consoleLogger) Warning(v ...interface{}) error {
	c.warn.Print(v...)
	return nil
}
func (c consoleLogger) Info(v ...interface{}) error {
	c.info.Print(v...)
	return nil
}
func (c consoleLogger) Errorf(format string, a ...interface{}) error {
	c.err.Printf(format, a...)
	return nil
}
func (c consoleLogger) Warningf(format string, a ...interface{}) error {
	c.warn.Printf(format, a...)
	return nil
}
func (c consoleLogger) Infof(format string, a ...interface{}) error {
	c.info.Printf(format, a...)
	return nil
}

const (
	optionKeepAlive            = "KeepAlive"
	optionKeepAliveDefault     = true
	optionRunAtLoad            = "RunAtLoad"
	optionRunAtLoadDefault     = false
	optionUserService          = "UserService"
	optionUserServiceDefault   = false
	optionSessionCreate        = "SessionCreate"
	optionSessionCreateDefault = false
	optionLogOutput            = "LogOutput"
	optionLogOutputDefault     = false
	optionPrefix               = "Prefix"
	optionPrefixDefault        = "application"

	optionRunWait      = "RunWait"
	optionReloadSignal = "ReloadSignal"
	optionPIDFile      = "PIDFile"
	optionRestart      = "Restart"

	optionSuccessExitStatus = "SuccessExitStatus"

	optionSystemdScript = "SystemdScript"
	optionSysvScript    = "SysvScript"
	optionUpstartScript = "UpstartScript"
	optionLaunchdConfig = "LaunchdConfig"
)

// Status represents service status as an byte value
type Status byte

// Status of service represented as an byte
const (
	StatusUnknown Status = iota // 由于错误或无法安装而无法确定状态
	StatusRunning
	StatusStopped
)

// Config提供服务的设置 Name字段是必需的
type Config struct {
	Name        string   // Required name of the service. No spaces suggested.
	DisplayName string   // Display name, spaces allowed.
	Description string   // Long description of service.
	UserName    string   // Run as username.
	Arguments   []string // Run with arguments.
	StartType   string
	//可选字段，用于指定服务的可执行文件。
	//如果为空，则使用当前可执行文件。
	Executable string

	// 服务依赖项数组
	//   注意，这些行将直接附加到以下代码的[Unit]
	//   生成的服务配置文件将不会检查其正确性
	Dependencies []string

	Option KeyValue
}

// 基于服务接口和配置创建新服务
func New(i Interface, c *Config) (Service, error) {
	if len(c.Name) == 0 {
		return nil, ErrNameFieldRequired
	}
	if system == nil {
		return nil, ErrNoServiceSystemDetected
	}
	return system.New(i, c)
}

// KeyValue提供了平台特定选项的列表
type KeyValue map[string]interface{}

// bool返回给定名称的值，假设该值是布尔值
// 如果找不到该值或该值不是类型，则返回defaultValue
func (kv KeyValue) bool(name string, defaultValue bool) bool {
	if v, found := kv[name]; found {
		if castValue, is := v.(bool); is {
			return castValue
		}
	}
	return defaultValue
}

// int returns the value of the given name, assuming the value is an int.
// If the value isn't found or is not of the type, the defaultValue is returned.
func (kv KeyValue) int(name string, defaultValue int) int {
	if v, found := kv[name]; found {
		if castValue, is := v.(int); is {
			return castValue
		}
	}
	return defaultValue
}

// string returns the value of the given name, assuming the value is a string.
// If the value isn't found or is not of the type, the defaultValue is returned.
func (kv KeyValue) string(name string, defaultValue string) string {
	if v, found := kv[name]; found {
		if castValue, is := v.(string); is {
			return castValue
		}
	}
	return defaultValue
}

// float64 returns the value of the given name, assuming the value is a float64.
// If the value isn't found or is not of the type, the defaultValue is returned.
func (kv KeyValue) float64(name string, defaultValue float64) float64 {
	if v, found := kv[name]; found {
		if castValue, is := v.(float64); is {
			return castValue
		}
	}
	return defaultValue
}

// funcSingle returns the value of the given name, assuming the value is a float64.
// If the value isn't found or is not of the type, the defaultValue is returned.
func (kv KeyValue) funcSingle(name string, defaultValue func()) func() {
	if v, found := kv[name]; found {
		if castValue, is := v.(func()); is {
			return castValue
		}
	}
	return defaultValue
}

// Platform 返回对系统服务的描述
func Platform() string {
	if system == nil {
		return ""
	}
	return system.String()
}

// 如果在OS服务管理器下运行，则Interactive返回false，否则返回true
func Interactive() bool {
	if system == nil {
		return true
	}
	return system.Interactive()
}

func newSystem() System {
	for _, choice := range systemRegistry {
		if choice.Detect() == false {
			continue
		}
		return choice
	}
	return nil
}

// ChooseSystem chooses a system from the given system services.
// SystemServices are considered in the order they are suggested.
// Calling this may change what Interactive and Platform return.
func ChooseSystem(a ...System) {
	systemRegistry = a
	system = newSystem()
}

// ChosenSystem returns the system that service will use.
func ChosenSystem() System {
	return system
}

// AvailableSystems returns the list of system services considered
// when choosing the system service.
func AvailableSystems() []System {
	return systemRegistry
}

// System represents the service manager that is available.
type System interface {
	// String returns a description of the system.
	String() string

	// Detect returns true if the system is available to use.
	Detect() bool

	// Interactive returns false if running under the system service manager
	// and true otherwise.
	Interactive() bool

	// New creates a new service for this system.
	New(i Interface, c *Config) (Service, error)
}

// Interface表示程序的服务接口。开始运行之前
//向宿主进程授予控制权，并在返回控制权时停止运行。
//
//   1. OS服务管理器执行用户程序
//   2. 用户程序看到它是从服务管理器执行的(IsInteractive为false)
//   3. 用户程序调用阻塞的Service.Run()
//   4. 调用Interface.Start()并快速返回
//   5. 用户程序运行
//   6. OS服务管理器向用户程序发出停止信号
//   7. 调用Interface.Stop()并快速返回
//      - For a successful exit, os.Exit should not be called in Interface.Stop().
//   8. Service.Run returns.
//   9. User program should quickly exit.
type Interface interface {
	// Start provides a place to initiate the service. The service doesn't not
	// signal a completed start until after this function returns, so the
	// Start function must not take more then a few seconds at most.
	Start(s Service) error

	// Stop provides a place to clean up program execution before it is terminated.
	// It should not take more then a few seconds to execute.
	// Stop should not call os.Exit directly in the function.
	Stop(s Service) error
}

// Service represents a service that can be run or controlled.
type Service interface {
	// Run should be called shortly after the program entry point.
	// After Interface.Stop has finished running, Run will stop blocking.
	// After Run stops blocking, the program must exit shortly after.
	Run() error

	// Start signals to the OS service manager the given service should start.
	Start() error

	// Stop signals to the OS service manager the given service should stop.
	Stop() error

	// Restart signals to the OS service manager the given service should stop then start.
	Restart() error

	// Install setups up the given service in the OS service manager. This may require
	// greater rights. Will return an error if it is already installed.
	Install() error

	// Uninstall removes the given service from the OS service manager. This may require
	// greater rights. Will return an error if the service is not present.
	Uninstall() error

	// Opens and returns a system logger. If the user program is running
	// interactively rather then as a service, the returned logger will write to
	// os.Stderr. If errs is non-nil errors will be sent on errs as well as
	// returned from Logger's functions.
	Logger(errs chan<- error) (Logger, error)

	// SystemLogger opens and returns a system logger. If errs is non-nil errors
	// will be sent on errs as well as returned from Logger's functions.
	SystemLogger(errs chan<- error) (Logger, error)

	// String displays the name of the service. The display name if present,
	// otherwise the name.
	String() string

	// Platform displays the name of the system that manages the service.
	// In most cases this will be the same as service.Platform().
	Platform() string

	// Status returns the current service status.
	Status() (Status, error)
}

// Control 从给定的 action string 向service传递控制方法.
func Control(s Service, action string) error {
	var err error
	switch action {
	case ControlAction[0]:
		err = s.Start()
	case ControlAction[1]:
		err = s.Stop()
	case ControlAction[2]:
		err = s.Restart()
	case ControlAction[3]:
		err = s.Install()
	case ControlAction[4]:
		err = s.Uninstall()
	default:
		err = fmt.Errorf("Unknown action %s", action)
	}
	if err != nil {
		return fmt.Errorf("Failed to %s %v: %v", action, s, err)
	}
	return nil
}

// Logger 写进系统日志
type Logger interface {
	Error(v ...interface{}) error
	Warning(v ...interface{}) error
	Info(v ...interface{}) error

	Errorf(format string, a ...interface{}) error
	Warningf(format string, a ...interface{}) error
	Infof(format string, a ...interface{}) error
}

const version = "windows-service"

type windowsService struct {
	i Interface
	*Config

	errSync      sync.Mutex
	stopStartErr error
}

// WindowsLogger 允许使用Windows特定的日志记录方法
type WindowsLogger struct {
	ev   *eventlog.Log
	errs chan<- error
}

type windowsSystem struct{}

func (windowsSystem) String() string {
	return version
}
func (windowsSystem) Detect() bool {
	return true
}
func (windowsSystem) Interactive() bool {
	return interactive
}
func (windowsSystem) New(i Interface, c *Config) (Service, error) {
	ws := &windowsService{
		i:      i,
		Config: c,
	}
	return ws, nil
}

func (l WindowsLogger) send(err error) error {
	if err == nil {
		return nil
	}
	if l.errs != nil {
		l.errs <- err
	}
	return err
}

// Error logs an error message.
func (l WindowsLogger) Error(v ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprint(v...)))
}

// Warning logs an warning message.
func (l WindowsLogger) Warning(v ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprint(v...)))
}

// Info logs an info message.
func (l WindowsLogger) Info(v ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprint(v...)))
}

// Errorf logs an error message.
func (l WindowsLogger) Errorf(format string, a ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprintf(format, a...)))
}

// Warningf logs an warning message.
func (l WindowsLogger) Warningf(format string, a ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprintf(format, a...)))
}

// Infof logs an info message.
func (l WindowsLogger) Infof(format string, a ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprintf(format, a...)))
}

// NError logs an error message and an event ID.
func (l WindowsLogger) NError(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprint(v...)))
}

// NWarning logs an warning message and an event ID.
func (l WindowsLogger) NWarning(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprint(v...)))
}

// NInfo logs an info message and an event ID.
func (l WindowsLogger) NInfo(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprint(v...)))
}

// NErrorf logs an error message and an event ID.
func (l WindowsLogger) NErrorf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprintf(format, a...)))
}

// NWarningf logs an warning message and an event ID.
func (l WindowsLogger) NWarningf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprintf(format, a...)))
}

// NInfof logs an info message and an event ID.
func (l WindowsLogger) NInfof(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprintf(format, a...)))
}

func (ws *windowsService) String() string {
	if len(ws.DisplayName) > 0 {
		return ws.DisplayName
	}
	return ws.Name
}

func (ws *windowsService) Platform() string {
	return version
}

func (ws *windowsService) setError(err error) {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	ws.stopStartErr = err
}
func (ws *windowsService) getError() error {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	return ws.stopStartErr
}

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if err := ws.i.Start(ws); err != nil {
		ws.setError(err)
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			if err := ws.i.Stop(ws); err != nil {
				ws.setError(err)
				return true, 2
			}
			break loop
		default:
			continue loop
		}
	}

	return false, 0
}

func (ws *windowsService) Install() error {
	exepath, err := ws.execPath()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ws.Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ws.Name)
	}
	s, err = m.CreateService(ws.Name, exepath, mgr.Config{
		DisplayName:      ws.DisplayName,
		Description:      ws.Description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: ws.UserName,
		Password:         ws.Option.string("Password", ""),
		Dependencies:     ws.Dependencies,
	}, ws.Arguments...)
	if err != nil {
		return err
	}
	defer s.Close()
	err = eventlog.InstallAsEventCreate(ws.Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if !strings.Contains(err.Error(), "exists") {
			s.Delete()
			return fmt.Errorf("SetupEventLogSource() failed: %s", err)
		}
	}
	return nil
}

func (ws *windowsService) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ws.Name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ws.Name)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(ws.Name)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}

func (ws *windowsService) Run() error {
	ws.setError(nil)
	if !interactive {
		// Return error messages from start and stop routines
		// that get executed in the Execute method.
		// Guarded with a mutex as it may run a different thread
		// (callback from windows).
		runErr := svc.Run(ws.Name, ws)
		startStopErr := ws.getError()
		if startStopErr != nil {
			return startStopErr
		}
		if runErr != nil {
			return runErr
		}
		return nil
	}
	err := ws.i.Start(ws)
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal)

	signal.Notify(sigChan, os.Interrupt)

	<-sigChan

	return ws.i.Stop(ws)
}

func (ws *windowsService) Status() (Status, error) {
	m, err := mgr.Connect()
	if err != nil {
		return StatusUnknown, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		if err.Error() == "The specified service does not exist as an installed service." {
			return StatusUnknown, ErrNotInstalled
		}
		return StatusUnknown, err
	}

	status, err := s.Query()
	if err != nil {
		return StatusUnknown, err
	}

	switch status.State {
	case svc.StartPending:
		fallthrough
	case svc.Running:
		return StatusRunning, nil
	case svc.PausePending:
		fallthrough
	case svc.Paused:
		fallthrough
	case svc.ContinuePending:
		fallthrough
	case svc.StopPending:
		fallthrough
	case svc.Stopped:
		return StatusStopped, nil
	default:
		return StatusUnknown, fmt.Errorf("unknown status %v", status)
	}
}

func (ws *windowsService) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func (ws *windowsService) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	return ws.stopWait(s)
}

func (ws *windowsService) Restart() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	err = ws.stopWait(s)
	if err != nil {
		return err
	}

	return s.Start()
}

func (ws *windowsService) stopWait(s *mgr.Service) error {
	// First stop the service. Then wait for the service to
	// actually stop before starting it.
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeDuration := time.Millisecond * 50

	timeout := time.After(getStopTimeout() + (timeDuration * 2))
	tick := time.NewTicker(timeDuration)
	defer tick.Stop()

	for status.State != svc.Stopped {
		select {
		case <-tick.C:
			status, err = s.Query()
			if err != nil {
				return err
			}
		case <-timeout:
			break
		}
	}
	return nil
}

// getStopTimeout fetches the time before windows will kill the service.
func getStopTimeout() time.Duration {
	// For default and paths see https://support.microsoft.com/en-us/kb/146092
	defaultTimeout := time.Millisecond * 20000
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, registry.READ)
	if err != nil {
		return defaultTimeout
	}
	sv, _, err := key.GetStringValue("WaitToKillServiceTimeout")
	if err != nil {
		return defaultTimeout
	}
	v, err := strconv.Atoi(sv)
	if err != nil {
		return defaultTimeout
	}
	return time.Millisecond * time.Duration(v)
}

func (ws *windowsService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return ws.SystemLogger(errs)
}
func (ws *windowsService) SystemLogger(errs chan<- error) (Logger, error) {
	el, err := eventlog.Open(ws.Name)
	if err != nil {
		return nil, err
	}
	return WindowsLogger{el, errs}, nil
}

//最终执行

type program struct{}

func (p *program) Start(s Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	for {
		time.Sleep(time.Second)
		log.Println("running")
	}
}

func (p *program) Stop(s Service) error {
	return nil
}

func main() {
	svcConfig := &Config{
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
	s, err := New(prg, svcConfig)
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
