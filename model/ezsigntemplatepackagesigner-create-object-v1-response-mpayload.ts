/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for POST /1/object/ezsigntemplatepackagesigner
 * @export
 * @interface EzsigntemplatepackagesignerCreateObjectV1ResponseMPayload
 */
export interface EzsigntemplatepackagesignerCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplatepackagesignerCreateObjectV1ResponseMPayload
     */
    /*'a_pkiEzsigntemplatepackagesignerID': Array<number>;*/
    'a_pkiEzsigntemplatepackagesignerID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepackagesignerCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatepackagesignerID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatepackagesignerCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackagesignerCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatepackagesignerID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


