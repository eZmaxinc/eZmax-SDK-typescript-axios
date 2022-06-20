/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignsignatures
 * @export
 * @interface EzsigndocumentGetEzsignsignaturesV1ResponseMPayload
 */
export interface EzsigndocumentGetEzsignsignaturesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsigndocumentGetEzsignsignaturesV1ResponseMPayload
     */
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
}

