/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Ezsigntemplatepackagesignermembership Object
 * @export
 * @interface EzsigntemplatepackagesignermembershipResponse
 */
export interface EzsigntemplatepackagesignermembershipResponse {
    /**
     * The unique ID of the Ezsigntemplatepackagesignermembership
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipResponse
     */
    'pkiEzsigntemplatepackagesignermembershipID': number;
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipResponse
     */
    'fkiEzsigntemplatepackagemembershipID': number;
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipResponse
     */
    'fkiEzsigntemplatepackagesignerID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipResponse
     */
    'fkiEzsigntemplatesignerID': number;
    /**
     * The Copy number in case of multiple copies.
     * @type {number}
     * @memberof EzsigntemplatepackagesignermembershipResponse
     */
    'iEzsigntemplatepackagesignermembershipCopy'?: number;
}
/**
 * A EzsigntemplatepackagesignermembershipResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignermembershipResponse
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipResponse extends DefaultObject {
   pkiEzsigntemplatepackagesignermembershipID:number = 0
   fkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}


