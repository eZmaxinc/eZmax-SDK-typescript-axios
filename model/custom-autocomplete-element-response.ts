/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'sValue': string;
    /**
     * The Unique ID of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     * @deprecated
     */
    'mValue'?: string;
    /**
     * Indicates if the element is active
     * @type {boolean}
     * @memberof CustomAutocompleteElementResponse
     */
    'bActive': boolean;
}
/**
 * A CustomAutocompleteElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomAutocompleteElementResponse
 */
export class DefaultObjectCustomAutocompleteElementResponse extends DefaultObject {
   sCategory:string = ''
   sLabel:string = ''
   sValue:string = ''
   mValue?:string = undefined
   bActive:boolean = false
}


