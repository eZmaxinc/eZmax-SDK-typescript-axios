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


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureRequestCompound } from './ezsigntemplatesignature-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
 */
export interface EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatesignatureRequestCompound>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
     */
    'a_objEzsigntemplatesignature': Array<EzsigntemplatesignatureRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request {
   a_objEzsigntemplatesignature:Array<EzsigntemplatesignatureRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request {
   a_objEzsigntemplatesignature = {
      type: 'array',
      required: true
   }
} 


