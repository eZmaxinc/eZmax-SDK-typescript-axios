/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FranchisereferalincomeRequest } from './franchisereferalincome-request';
import { FranchisereferalincomeRequestCompound } from './franchisereferalincome-request-compound';

/**
 * Request for POST /1/object/franchisereferalincome
 * @export
 * @interface FranchisereferalincomeCreateObjectV1Request
 */
export interface FranchisereferalincomeCreateObjectV1Request {
    /**
     * 
     * @type {FranchisereferalincomeRequest}
     * @memberof FranchisereferalincomeCreateObjectV1Request
     */
    'objFranchisereferalincome'?: FranchisereferalincomeRequest;
    /**
     * 
     * @type {FranchisereferalincomeRequestCompound}
     * @memberof FranchisereferalincomeCreateObjectV1Request
     */
    'objFranchisereferalincomeCompound'?: FranchisereferalincomeRequestCompound;
}

