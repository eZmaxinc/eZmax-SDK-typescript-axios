/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Generic AutocompleteElement Response
 * @export
 * @interface CustomAutocompleteElementResponse
 */
export interface CustomAutocompleteElementResponse {
    /**
     * The Category for the dropdown or an empty string if not categorized
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'sCategory': string;
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'sLabel': string;
    /**
     * The Unique ID of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'mValue': string;
}

