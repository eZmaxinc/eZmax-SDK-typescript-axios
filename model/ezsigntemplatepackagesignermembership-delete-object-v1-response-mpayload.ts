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



import { DefaultObject } from '../base'

/**
 * Payload for DELETE /1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}
 * @export
 * @interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload
 */
export interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload {
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload
     */
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload
     */
    'bEzsignbulksendNeedvalidation': boolean;
}
/**
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload extends DefaultObject {
   bEzsigntemplatepackageNeedvalidation:boolean = false
   bEzsignbulksendNeedvalidation:boolean = false
}


