/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeRequest } from './franchisereferalincome-request';
// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeRequestCompound } from './franchisereferalincome-request-compound';

import { DefaultObject } from '../base'

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
/**
 * A FranchisereferalincomeCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeCreateObjectV1Request
 */
export class DefaultObjectFranchisereferalincomeCreateObjectV1Request extends DefaultObject {
   objFranchisereferalincome?:Partial<FranchisereferalincomeRequest> = undefined
   objFranchisereferalincomeCompound?:Partial<FranchisereferalincomeRequestCompound> = undefined
}


