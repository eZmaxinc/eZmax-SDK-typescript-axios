/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigndocumentlogResponse } from './ezsigndocumentlog-response';

/**
 * Payload for the /1/object/ezsigndocument/{pkiEzsigndocumentID}/getTemporaryProof API Request
 * @export
 * @interface EzsigndocumentGetTemporaryProofV1ResponseMPayload
 */
export interface EzsigndocumentGetTemporaryProofV1ResponseMPayload {
    /**
     * 
     * @type {EzsigndocumentlogResponse}
     * @memberof EzsigndocumentGetTemporaryProofV1ResponseMPayload
     */
    'a_objEzsigndocumentlog': EzsigndocumentlogResponse;
}

