/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignformfieldRequest } from './custom-ezsignformfield-request';

/**
 * A Custom Ezsignformfieldgroup Object to fill an Ezsignform using submitForm
 * @export
 * @interface CustomEzsignformfieldgroupRequest
 */
export interface CustomEzsignformfieldgroupRequest {
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof CustomEzsignformfieldgroupRequest
     */
    /*'pkiEzsignformfieldgroupID'?: number;*/
    'pkiEzsignformfieldgroupID'?: number;
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof CustomEzsignformfieldgroupRequest
     */
    /*'sEzsignformfieldgroupLabel'?: string;*/
    'sEzsignformfieldgroupLabel'?: string;
    /**
     * An array containing all the values to fill the Ezsignform.
     * @type {Array<CustomEzsignformfieldRequest>}
     * @memberof CustomEzsignformfieldgroupRequest
     */
    /*'a_objEzsignformfield': Array<CustomEzsignformfieldRequest>;*/
    'a_objEzsignformfield': Array<CustomEzsignformfieldRequest>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignformfieldgroupRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignformfieldgroupRequest
 */
export class DataObjectCustomEzsignformfieldgroupRequest {
   pkiEzsignformfieldgroupID?:number = undefined
   sEzsignformfieldgroupLabel?:string = undefined
   a_objEzsignformfield:Array<CustomEzsignformfieldRequest> = []
}

/**
 * @export 
 * A CustomEzsignformfieldgroupRequest Validation Object
 * @class ValidationObjectCustomEzsignformfieldgroupRequest
 */
export class ValidationObjectCustomEzsignformfieldgroupRequest {
   pkiEzsignformfieldgroupID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignformfieldgroupLabel = {
      type: 'string',
      minLength: 1,
      maxLength: 50,
      required: false
   }
   a_objEzsignformfield = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


