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
 * A Ezsigntemplatepackagemembership Object
 * @export
 * @interface EzsigntemplatepackagemembershipResponse
 */
export interface EzsigntemplatepackagemembershipResponse {
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipResponse
     */
    'pkiEzsigntemplatepackagemembershipID': number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipResponse
     */
    'fkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipResponse
     */
    'fkiEzsigntemplateID': number;
    /**
     * The order in which the Ezsigntemplate will be imported when using an Ezsigntemplatepackage.
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipResponse
     */
    'iEzsigntemplatepackagemembershipOrder': number;
}
/**
 * A EzsigntemplatepackagemembershipResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagemembershipResponse
 */
export class DefaultObjectEzsigntemplatepackagemembershipResponse extends DefaultObject {
   pkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   fkiEzsigntemplateID:number = 0
   iEzsigntemplatepackagemembershipOrder:number = 0
}


