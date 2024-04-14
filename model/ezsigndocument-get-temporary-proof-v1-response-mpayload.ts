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


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentlogResponseCompound } from './ezsigndocumentlog-response-compound';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getTemporaryProof
 * @export
 * @interface EzsigndocumentGetTemporaryProofV1ResponseMPayload
 */
export interface EzsigndocumentGetTemporaryProofV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigndocumentlogResponseCompound>}
     * @memberof EzsigndocumentGetTemporaryProofV1ResponseMPayload
     */
    /*'a_objEzsigndocumentlog': Array<EzsigndocumentlogResponseCompound>;*/
    'a_objEzsigndocumentlog': Array<EzsigndocumentlogResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentGetTemporaryProofV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload {
   a_objEzsigndocumentlog:Array<EzsigndocumentlogResponseCompound> = []
}

/**
 * @export 
 * A EzsigndocumentGetTemporaryProofV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload {
   a_objEzsigndocumentlog = {
      type: 'array',
      required: true
   }
} 


