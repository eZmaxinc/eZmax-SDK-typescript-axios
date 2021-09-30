/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { AddressRequest } from './address-request';
import { ContactRequestCompound } from './contact-request-compound';
import { FranchisereferalincomeRequest } from './franchisereferalincome-request';
import { FranchisereferalincomeRequestCompoundAllOf } from './franchisereferalincome-request-compound-all-of';



/**
 * A Franchisereferalincome Object and children to create a complete structure
 * @export
 * @interface FranchisereferalincomeRequestCompound
 */
export interface FranchisereferalincomeRequestCompound {
    /**
     * 
     * @type {AddressRequest}
     * @memberof FranchisereferalincomeRequestCompound
     */
    objAddress: AddressRequest;
    /**
     * 
     * @type {Array<ContactRequestCompound>}
     * @memberof FranchisereferalincomeRequestCompound
     */
    a_objContact: Array<ContactRequestCompound>;
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof FranchisereferalincomeRequestCompound
     */
    fkiFranchisebrokerID: number;
    /**
     * The unique ID of the Franchisereferalincomeprogram
     * @type {number}
     * @memberof FranchisereferalincomeRequestCompound
     */
    fkiFranchisereferalincomeprogramID: number;
    /**
     * The unique ID of the Period
     * @type {number}
     * @memberof FranchisereferalincomeRequestCompound
     */
    fkiPeriodID: number;
    /**
     * The loan amount
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    dFranchisereferalincomeLoan: string;
    /**
     * The amount that will be given to the franchise
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    dFranchisereferalincomeFranchiseamount: string;
    /**
     * The amount that will be kept by the franchisor
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    dFranchisereferalincomeFranchisoramount: string;
    /**
     * The amount that will be given to the agent
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    dFranchisereferalincomeAgentamount: string;
    /**
     * The date the amounts were disbursed
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    dtFranchisereferalincomeDisbursed: string;
    /**
     * A comment about the transaction
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    tFranchisereferalincomeComment: string;
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof FranchisereferalincomeRequestCompound
     */
    fkiFranchiseofficeID: number;
    /**
     * 
     * @type {string}
     * @memberof FranchisereferalincomeRequestCompound
     */
    sFranchisereferalincomeRemoteid: string;
}
