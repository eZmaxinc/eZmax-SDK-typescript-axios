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
import { CustomEzsignformfieldgroupRequest } from './custom-ezsignformfieldgroup-request';

/**
 * Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/submitEzsignform
 * @export
 * @interface EzsigndocumentSubmitEzsignformV1Request
 */
export interface EzsigndocumentSubmitEzsignformV1Request {
    /**
     * Whether the Ezsignform submitted is a draft or not.
     * @type {boolean}
     * @memberof EzsigndocumentSubmitEzsignformV1Request
     */
    /*'bEzsignformIsdraft': boolean;*/
    'bEzsignformIsdraft': boolean;
    /**
     * 
     * @type {Array<CustomEzsignformfieldgroupRequest>}
     * @memberof EzsigndocumentSubmitEzsignformV1Request
     */
    /*'a_objEzsignformfieldgroup': Array<CustomEzsignformfieldgroupRequest>;*/
    'a_objEzsignformfieldgroup': Array<CustomEzsignformfieldgroupRequest>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentSubmitEzsignformV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentSubmitEzsignformV1Request
 */
export class DataObjectEzsigndocumentSubmitEzsignformV1Request {
   bEzsignformIsdraft:boolean = false
   a_objEzsignformfieldgroup:Array<CustomEzsignformfieldgroupRequest> = []
}

/**
 * @export 
 * A EzsigndocumentSubmitEzsignformV1Request Validation Object
 * @class ValidationObjectEzsigndocumentSubmitEzsignformV1Request
 */
export class ValidationObjectEzsigndocumentSubmitEzsignformV1Request {
   bEzsignformIsdraft = {
      type: 'boolean',
      required: true
   }
   a_objEzsignformfieldgroup = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


