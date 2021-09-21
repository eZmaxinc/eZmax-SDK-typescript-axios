/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */





/**
 * Payload for the /1/object/ezsignsignature/createObject API Request
 * @export
 * @interface EzsignsignatureCreateObjectV1ResponseMPayload
 */
export interface EzsignsignatureCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsignsignatureCreateObjectV1ResponseMPayload
     */
    a_pkiEzsignsignatureID: Array<number>;
}
