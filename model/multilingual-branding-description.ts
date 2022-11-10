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
 * Description of the Branding
 * @export
 * @interface MultilingualBrandingDescription
 */
export interface MultilingualBrandingDescription {
    /**
     * The description of the Branding in French
     * @type {string}
     * @memberof MultilingualBrandingDescription
     */
    'sBrandingDescription1'?: string;
    /**
     * The description of the Branding in English
     * @type {string}
     * @memberof MultilingualBrandingDescription
     */
    'sBrandingDescription2'?: string;
}
/**
 * A MultilingualBrandingDescription Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualBrandingDescription
 */
export class DefaultObjectMultilingualBrandingDescription extends DefaultObject {
   sBrandingDescription1?:string = undefined
   sBrandingDescription2?:string = undefined
}


