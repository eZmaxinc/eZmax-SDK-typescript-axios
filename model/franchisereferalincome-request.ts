/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * An Franchisereferalincome Object
 * @export
 * @interface FranchisereferalincomeRequest
 */
export interface FranchisereferalincomeRequest {
    /**
     * The unique ID of the Franchisereferalincome
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    'pkiFranchisereferalincomeID'?: number;
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    'fkiFranchisebrokerID': number;
    /**
     * The unique ID of the Franchisereferalincomeprogram
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    'fkiFranchisereferalincomeprogramID': number;
    /**
     * The unique ID of the Period
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    'fkiPeriodID': number;
    /**
     * The loan amount
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'dFranchisereferalincomeLoan': string;
    /**
     * The amount that will be given to the franchise
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'dFranchisereferalincomeFranchiseamount': string;
    /**
     * The amount that will be kept by the franchisor
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'dFranchisereferalincomeFranchisoramount': string;
    /**
     * The amount that will be given to the agent
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'dFranchisereferalincomeAgentamount': string;
    /**
     * The date the amounts were disbursed
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'dtFranchisereferalincomeDisbursed': string;
    /**
     * Comment about the transaction
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'tFranchisereferalincomeComment': string;
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    'fkiFranchiseofficeID': number;
    /**
     * 
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    'sFranchisereferalincomeRemoteid': string;
}
/**
 * A FranchisereferalincomeRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeRequest
 */
export class DefaultObjectFranchisereferalincomeRequest extends DefaultObject {
   pkiFranchisereferalincomeID?:number = undefined
   fkiFranchisebrokerID:number = 0
   fkiFranchisereferalincomeprogramID:number = 0
   fkiPeriodID:number = 0
   dFranchisereferalincomeLoan:string = ''
   dFranchisereferalincomeFranchiseamount:string = ''
   dFranchisereferalincomeFranchisoramount:string = ''
   dFranchisereferalincomeAgentamount:string = ''
   dtFranchisereferalincomeDisbursed:string = ''
   tFranchisereferalincomeComment:string = ''
   fkiFranchiseofficeID:number = 0
   sFranchisereferalincomeRemoteid:string = ''
}


