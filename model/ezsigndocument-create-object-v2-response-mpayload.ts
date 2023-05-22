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



/**
 * Payload for POST /2/object/ezsigndocument
 * @export
 * @interface EzsigndocumentCreateObjectV2ResponseMPayload
 */
export interface EzsigndocumentCreateObjectV2ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigndocumentCreateObjectV2ResponseMPayload
     */
    'a_pkiEzsigndocumentID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentCreateObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentCreateObjectV2ResponseMPayload
 */
export class DataObjectEzsigndocumentCreateObjectV2ResponseMPayload {
   a_pkiEzsigndocumentID:Array<number> = []
}

/**
 * @export 
 * A EzsigndocumentCreateObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentCreateObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigndocumentCreateObjectV2ResponseMPayload {
   a_pkiEzsigndocumentID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


