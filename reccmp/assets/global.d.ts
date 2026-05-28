import {
  ReccmpFilterTypeEvent,
  ReccmpHidePerfectEvent,
  ReccmpHideStubEvent,
  ReccmpNextPageEvent,
  ReccmpPageSizeEvent,
  ReccmpPrevPageEvent,
  ReccmpQueryEvent,
  ReccmpQueryRegexEvent,
  ReccmpRegisterEvent,
  ReccmpSetPageEvent,
  ReccmpShowRecompEvent,
  ReccmpSortColEvent,
  ReccmpTableEvent,
  ReccmpToggleExpandedEvent,
} from './events';

declare global {
  interface HTMLElementEventMap {
    [ReccmpRegisterEvent.eventName]: ReccmpRegisterEvent;
    [ReccmpTableEvent.eventName]: ReccmpTableEvent;
    [ReccmpSetPageEvent.eventName]: ReccmpSetPageEvent;
    [ReccmpQueryEvent.eventName]: ReccmpQueryEvent;
    [ReccmpQueryRegexEvent.eventName]: ReccmpQueryRegexEvent;
    [ReccmpFilterTypeEvent.eventName]: ReccmpFilterTypeEvent;
    [ReccmpHidePerfectEvent.eventName]: ReccmpHidePerfectEvent;
    [ReccmpHideStubEvent.eventName]: ReccmpHideStubEvent;
    [ReccmpShowRecompEvent.eventName]: ReccmpShowRecompEvent;
    [ReccmpPrevPageEvent.eventName]: ReccmpPrevPageEvent;
    [ReccmpNextPageEvent.eventName]: ReccmpNextPageEvent;
    [ReccmpSortColEvent.eventName]: ReccmpSortColEvent;
    [ReccmpPageSizeEvent.eventName]: ReccmpPageSizeEvent;
    [ReccmpToggleExpandedEvent.eventName]: ReccmpToggleExpandedEvent;
  }
}
