/** @import { ReccmpInternalState } from '../types' */

import { ReccmpQueryEvent, ReccmpQueryRegexEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class SearchBar extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<input type="search"></input><label><input type="checkbox" />RE</label>`;
    const input = /** @type {HTMLInputElement} */ (this.querySelector('input[type=search]'));
    input.addEventListener('input', (evt) => {
      this.dispatchEvent(new ReccmpQueryEvent(/** @type {HTMLInputElement} */ (evt.target).value));
    });
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.addEventListener('change', (evt) => {
      this.dispatchEvent(new ReccmpQueryRegexEvent(/** @type {HTMLInputElement} */ (evt.target).checked));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ query, queryRegex, filterType }) {
    const input = /** @type {HTMLInputElement} */ (this.querySelector('input[type=search]'));
    input.value = query;
    input.placeholder = filterType === 1 ? 'Search for offset or function name...' : 'Search for instruction...';
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.checked = queryRegex;
  }
}
// reccmp-pack-end

export default SearchBar;
