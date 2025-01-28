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
import type { EzsigndocumentdependencyRequestCompound } from './ezsigndocumentdependency-request-compound';

/**
 * Request for POST /2/object/ezsignfolder/{pkiEzsignfolderID}/reorder
 * @export
 * @interface CustomEzsigndocumentRequest
 */
export interface CustomEzsigndocumentRequest {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof CustomEzsigndocumentRequest
     */
    /*'pkiEzsigndocumentID': number;*/
    'pkiEzsigndocumentID': number;
    /**
     * 
     * @type {Array<EzsigndocumentdependencyRequestCompound>}
     * @memberof CustomEzsigndocumentRequest
     */
    /*'a_objEzsigndocumentdependency': Array<EzsigndocumentdependencyRequestCompound>;*/
    'a_objEzsigndocumentdependency': Array<EzsigndocumentdependencyRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsigndocumentRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsigndocumentRequest
 */
export class DataObjectCustomEzsigndocumentRequest {
   pkiEzsigndocumentID:number = 0
   a_objEzsigndocumentdependency:Array<EzsigndocumentdependencyRequestCompound> = []
}

/**
 * @export 
 * A CustomEzsigndocumentRequest Validation Object
 * @class ValidationObjectCustomEzsigndocumentRequest
 */
export class ValidationObjectCustomEzsigndocumentRequest {
   pkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   a_objEzsigndocumentdependency = {
      type: 'array',
      required: true
   }
} 


