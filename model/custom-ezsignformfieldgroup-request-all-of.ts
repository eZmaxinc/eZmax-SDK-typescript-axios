/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
 * 
 * @export
 * @interface CustomEzsignformfieldgroupRequestAllOf
 */
export interface CustomEzsignformfieldgroupRequestAllOf {
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof CustomEzsignformfieldgroupRequestAllOf
     */
    'pkiEzsignformfieldgroupID'?: number;
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof CustomEzsignformfieldgroupRequestAllOf
     */
    'sEzsignformfieldgroupLabel'?: string;
    /**
     * An array containing all the values to fill the Ezsignform.
     * @type {Array<CustomEzsignformfieldRequest>}
     * @memberof CustomEzsignformfieldgroupRequestAllOf
     */
    'a_objEzsignformfield': Array<CustomEzsignformfieldRequest>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignformfieldgroupRequestAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignformfieldgroupRequestAllOf
 */
export class DataObjectCustomEzsignformfieldgroupRequestAllOf {
   pkiEzsignformfieldgroupID?:number = undefined
   sEzsignformfieldgroupLabel?:string = undefined
   a_objEzsignformfield:Array<CustomEzsignformfieldRequest> = []
}

/**
 * @export 
 * A CustomEzsignformfieldgroupRequestAllOf Validation Object
 * @class ValidationObjectCustomEzsignformfieldgroupRequestAllOf
 */
export class ValidationObjectCustomEzsignformfieldgroupRequestAllOf {
   pkiEzsignformfieldgroupID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignformfieldgroupLabel = {
      type: 'string',
      required: false
   }
   a_objEzsignformfield = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


