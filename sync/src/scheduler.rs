use collections::LinkedList;

use fringe::OwnedStack;
use fringe::session::ThreadLocals;
use fringe::session::cycle::{C1, Cycle};
use spin;
use void::Void;


/// Represents a thread that yeilded of its own accord, and does not expect anything
struct Yielded(C1<'static, OwnedStack, spin::MutexGuard<'static, Scheduler>>);

/// Queue of threadfs waiting to be run. Current thread is NOT in queue.
pub struct Scheduler {
  run_queue: LinkedList<Yielded>
}

pub type SchedulerCapability<'a> = spin::MutexGuard<'a, Scheduler>;

lazy_static! {
  static ref SCHEDULER: spin::Mutex<Scheduler> = spin::Mutex::new(Scheduler::new());
}

pub fn lock_scheduler() -> SchedulerCapability<'static> {
  SCHEDULER.lock()
}

impl Scheduler {
  pub fn new() -> Scheduler {
    Scheduler { run_queue: LinkedList::new() }
  }
}

fn put_back(old: Option<Yielded>, mut guard: &mut SchedulerCapability)
{
  let ctx = match old {
    None      => return,
    Some(ctx) => ctx,
  };
  guard.run_queue.push_back(ctx);
}
pub trait SchedulerCapabilityExt {
  #[inline]
  fn spawn<F>(&mut self, stack: OwnedStack, f: F)
    where F: FnOnce(&mut ThreadLocals<OwnedStack>) -> Void + Send + 'static;

  #[inline]
  fn yield_cur(self, maybe_stack: Option<&mut ThreadLocals<OwnedStack>>) -> Self;

  #[inline]
  fn exit(self, maybe_stack: Option<&mut ThreadLocals<OwnedStack>>) -> !;
}

impl SchedulerCapabilityExt for SchedulerCapability<'static> {
  #[inline]
  fn spawn<F>(&mut self, stack: OwnedStack, f: F)
    where F: FnOnce(&mut ThreadLocals<OwnedStack>) -> Void + Send + 'static
  {
    let ctx = C1::new(stack, |tls, (old, mut guard)| {
      put_back(old.map(Yielded), &mut guard);
      drop(guard);
      match f(tls) {}
    });
    self.run_queue.push_back(Yielded(ctx));
  }

  #[inline]
  fn yield_cur(mut self, maybe_stack: Option<&mut ThreadLocals<OwnedStack>>)
               -> Self
  {
    let next = match self.run_queue.pop_front() {
      Some(n) => n,
      None    => {
        info!("The run queue is empty, will not yield");
        return self
      },
    };
    let (old, mut guard) = next.0.swap(maybe_stack, self);
    put_back(old.map(Yielded), &mut guard);
    guard
  }

  #[inline]
  fn exit(mut self, maybe_stack: Option<&mut ThreadLocals<OwnedStack>>) -> !
  {
    let next = match self.run_queue.pop_front() {
      Some(n) => n,
      None    => {
        info!("The run queue is empty, will now \"shut down\"");
        drop(self); // In case we want to allow resurrections...
        ::abort()
      },
    };
    next.0.kontinue(maybe_stack, self)
  }
}

fn inner_thread_test(arg: usize) {
  debug!("arg is {}", arg)
}

fn test_thread(tl: &mut ThreadLocals<OwnedStack>) -> Void {
  debug!("in a test thread!");
  inner_thread_test(11);
  let s = lock_scheduler();
  debug!("leaving test thread!");
  s.exit(Some(tl))
}

pub fn thread_stuff(tl: &mut ThreadLocals<OwnedStack>) {
  debug!("starting thread test");
  let mut s = lock_scheduler();

  debug!("orig sched {:p}", &s);
  s.spawn(OwnedStack::new(512), test_thread);
  debug!("schedule okay");
  s = s.yield_cur(Some(tl));
  drop(s);
  debug!("back");
}
