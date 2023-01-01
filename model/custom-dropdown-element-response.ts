/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Generic DropdownElement Response
 * @export
 * @interface CustomDropdownElementResponse
 */
export interface CustomDropdownElementResponse {
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomDropdownElementResponse
     */
    'sLabel': string;
    /**
     * The Value of the element
     * @type {string}
     * @memberof CustomDropdownElementResponse
     */
    'sValue': string;
}
/**
 * A CustomDropdownElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomDropdownElementResponse
 */
export class DefaultObjectCustomDropdownElementResponse extends DefaultObject {
   sLabel:string = ''
   sValue:string = ''
}


