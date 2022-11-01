/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Generic DropdownElement Request
 * @export
 * @interface CustomDropdownElementRequest
 */
export interface CustomDropdownElementRequest {
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomDropdownElementRequest
     */
    'sLabel': string;
    /**
     * The Value of the element
     * @type {string}
     * @memberof CustomDropdownElementRequest
     */
    'sValue': string;
}
/**
 * A CustomDropdownElementRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomDropdownElementRequest
 */
export class DefaultObjectCustomDropdownElementRequest extends DefaultObject {
   sLabel:string = ''
   sValue:string = ''
}


