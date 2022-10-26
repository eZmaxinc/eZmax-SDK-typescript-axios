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
 * 
 * @export
 * @interface BrandingResponseCompoundAllOf
 */
export interface BrandingResponseCompoundAllOf {
    /**
     * The url of the picture used as logo in the Branding
     * @type {string}
     * @memberof BrandingResponseCompoundAllOf
     */
    'sBrandingLogourl'?: string;
}
/**
 * A BrandingResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingResponseCompoundAllOf
 */
export class DefaultObjectBrandingResponseCompoundAllOf extends DefaultObject {
   sBrandingLogourl?:string = undefined
}


