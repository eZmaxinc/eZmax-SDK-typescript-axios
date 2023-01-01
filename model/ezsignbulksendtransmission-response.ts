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


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';

import { DefaultObject } from '../base'

/**
 * An Ezsignbulksendtransmission Object
 * @export
 * @interface EzsignbulksendtransmissionResponse
 */
export interface EzsignbulksendtransmissionResponse {
    /**
     * The unique ID of the Ezsignbulksendtransmission
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponse
     */
    'pkiEzsignbulksendtransmissionID': number;
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponse
     */
    'fkiEzsignbulksendID': number;
    /**
     * The description of the Ezsignbulksendtransmission
     * @type {string}
     * @memberof EzsignbulksendtransmissionResponse
     */
    'sEzsignbulksendtransmissionDescription': string;
    /**
     * The number of errors during the Ezsignbulksendtransmission
     * @type {number}
     * @memberof EzsignbulksendtransmissionResponse
     */
    'iEzsignbulksendtransmissionErrors': number;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignbulksendtransmissionResponse
     */
    'objAudit': CommonAudit;
}
/**
 * A EzsignbulksendtransmissionResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendtransmissionResponse
 */
export class DefaultObjectEzsignbulksendtransmissionResponse extends DefaultObject {
   pkiEzsignbulksendtransmissionID:number = 0
   fkiEzsignbulksendID:number = 0
   sEzsignbulksendtransmissionDescription:string = ''
   iEzsignbulksendtransmissionErrors:number = 0
   objAudit:Partial<CommonAudit> = {}
}


