/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/object/ezsigntemplatepackagemembership
 * @export
 * @interface EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload
 */
export interface EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload
     */
    'a_pkiEzsigntemplatepackagemembershipID': Array<number>;
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload
     */
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload
     */
    'bEzsignbulksendNeedvalidation': boolean;
}
/**
 * A EzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagemembershipCreateObjectV1ResponseMPayload extends DefaultObject {
   a_pkiEzsigntemplatepackagemembershipID:Array<number> = []
   bEzsigntemplatepackageNeedvalidation:boolean = false
   bEzsignbulksendNeedvalidation:boolean = false
}


