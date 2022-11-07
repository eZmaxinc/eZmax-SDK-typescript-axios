/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentlogResponseCompound } from './ezsigndocumentlog-response-compound';

import { DefaultObject } from '../base'

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
    'a_objEzsigndocumentlog': Array<EzsigndocumentlogResponseCompound>;
}
/**
 * A EzsigndocumentGetTemporaryProofV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentGetTemporaryProofV1ResponseMPayload extends DefaultObject {
   a_objEzsigndocumentlog:Array<EzsigndocumentlogResponseCompound> = []
}


