/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Custom Ezsignformfield Object to fill an Ezsignform using submitForm
 * @export
 * @interface CustomEzsignformfieldRequest
 */
export interface CustomEzsignformfieldRequest {
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof CustomEzsignformfieldRequest
     */
    'pkiEzsignformfieldID'?: number;
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof CustomEzsignformfieldRequest
     */
    'sEzsignformfieldLabel'?: string;
    /**
     * Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof CustomEzsignformfieldRequest
     */
    'bEzsignformfieldSelected'?: boolean;
    /**
     * This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea**
     * @type {string}
     * @memberof CustomEzsignformfieldRequest
     */
    'sEzsignformfieldEnteredvalue'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignformfieldRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignformfieldRequest
 */
export class DataObjectCustomEzsignformfieldRequest {
   pkiEzsignformfieldID?:number = undefined
   sEzsignformfieldLabel?:string = undefined
   bEzsignformfieldSelected?:boolean = undefined
   sEzsignformfieldEnteredvalue?:string = undefined
}

/**
 * @export 
 * A CustomEzsignformfieldRequest Validation Object
 * @class ValidationObjectCustomEzsignformfieldRequest
 */
export class ValidationObjectCustomEzsignformfieldRequest {
   pkiEzsignformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignformfieldLabel = {
      type: 'string',
      required: false
   }
   bEzsignformfieldSelected = {
      type: 'boolean',
      required: false
   }
   sEzsignformfieldEnteredvalue = {
      type: 'string',
      required: false
   }
} 


