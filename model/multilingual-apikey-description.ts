/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Description of the API Key
 * @export
 * @interface MultilingualApikeyDescription
 */
export interface MultilingualApikeyDescription {
    /**
     * The description of the Apikey in French
     * @type {string}
     * @memberof MultilingualApikeyDescription
     */
    'sApikeyDescription1'?: string;
    /**
     * The description of the Apikey in English
     * @type {string}
     * @memberof MultilingualApikeyDescription
     */
    'sApikeyDescription2'?: string;
}
/**
 * A MultilingualApikeyDescription Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualApikeyDescription
 */
export class DefaultObjectMultilingualApikeyDescription extends DefaultObject {
   sApikeyDescription1?:string = undefined
   sApikeyDescription2?:string = undefined
}


