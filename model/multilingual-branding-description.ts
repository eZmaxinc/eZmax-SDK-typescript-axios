/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
    /*'sBrandingDescription1'?: string;*/
    'sBrandingDescription1'?: string;
    /**
     * The description of the Branding in English
     * @type {string}
     * @memberof MultilingualBrandingDescription
     */
    /*'sBrandingDescription2'?: string;*/
    'sBrandingDescription2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualBrandingDescription Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualBrandingDescription
 */
export class DataObjectMultilingualBrandingDescription {
   sBrandingDescription1?:string = undefined
   sBrandingDescription2?:string = undefined
}

/**
 * @export 
 * A MultilingualBrandingDescription Validation Object
 * @class ValidationObjectMultilingualBrandingDescription
 */
export class ValidationObjectMultilingualBrandingDescription {
   sBrandingDescription1 = {
      type: 'string',
      required: false
   }
   sBrandingDescription2 = {
      type: 'string',
      required: false
   }
} 


