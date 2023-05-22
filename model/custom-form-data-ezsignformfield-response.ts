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



/**
 * An Ezsignformfield Object
 * @export
 * @interface CustomFormDataEzsignformfieldResponse
 */
export interface CustomFormDataEzsignformfieldResponse {
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof CustomFormDataEzsignformfieldResponse
     */
    'sEzsignformfieldLabel': string;
    /**
     * The value for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is Checkbox or Radio
     * @type {string}
     * @memberof CustomFormDataEzsignformfieldResponse
     */
    'sEzsignformfieldValue': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomFormDataEzsignformfieldResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomFormDataEzsignformfieldResponse
 */
export class DataObjectCustomFormDataEzsignformfieldResponse {
   sEzsignformfieldLabel:string = ''
   sEzsignformfieldValue:string = ''
}

/**
 * @export 
 * A CustomFormDataEzsignformfieldResponse Validation Object
 * @class ValidationObjectCustomFormDataEzsignformfieldResponse
 */
export class ValidationObjectCustomFormDataEzsignformfieldResponse {
   sEzsignformfieldLabel = {
      type: 'string',
      required: true
   }
   sEzsignformfieldValue = {
      type: 'string',
      required: true
   }
} 


