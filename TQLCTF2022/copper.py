import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

import itertools

def coppersmith_bivariate(p, X, Y, k = 2, i_0 = 0, j_0 = 1, debug=True):
    """
    Implements Coron's simplification of Coppersmith's algorithm in the bivariate case: 
    https://www.iacr.org/archive/crypto2007/46220372/46220372.pdf
    Per the paper, Coron's simplification relies on the following result:
    Given some p(x, y) in Z[x, y], we can fix some arbitrary integer n and construct a lattice of polynomials 
    that are multiples of p(x, y) and n, and then reduce this lattice to obtain a polynomial h(x, y) with small coefficients such that 
    if h(x_0, y_0) = 0 (mod n) for some arbitrary integer n, then h(x_0, y_0) = 0 over Z holds as well. 
    :param p: bivariate polynomial p(x, y) in Z[x, y]
    :param X: Bound for root x_0 of p
    :param Y: Bound for root y_0 of p
    :param k: Determines size of the M matrix and the corresponding lattice L_2.
    :param i_0: index such that 0 <= i_0 <= deg(p), used to generate monomials x^(i + i_0)*y^(j + j_0)
    :param j_0: index such that 0 <= j_0 <= deg(p), used to generate monomials x^(i + i_0)*y^(j + j_0)
    :param debug: Turns on debugging information
    :return: The small roots x_0, y_0 of h(x, y) such that |x_0| <= X, |y_0| <= Y, and h(x_0, y_0) = 0 over Z
    """
    if len(p.variables()) != 2:
        raise ValueError("Given polynomial is not bivariate.")

    # We want to make sure that XY < W = max_ij(p_ij x^i y^j), otherwise there may not be a solution.
    d = max(p.degree(x), p.degree(y))
    W = 0

    if debug:
        print(f"Attempting to find small roots for the given polynomial over Z...")
        print(f"With parameters k = {k}, i_0 = {i_0}, j_0 = {j_0}")

    # Iterate through all the monomials of p to calculate W
    for term in p:
        p_ij, m = term
        i, j = m.degree(x), m.degree(y)
        W = max(W, p_ij * X^i * Y^j)
    
    if debug and X * Y > W^(2/(3*d)):
        print("Warning: XY > W^(2/(3*d)); a solution may not be found.")
    

    prods = list(itertools.product(range(k), range(k)))[::-1]
    prods_kd = list(itertools.product(range(k + d), range(k + d)))[::-1]
    terms = sorted([x^(i + i_0)*y^(j + j_0) for i, j in prods], reverse=True)
    
    # Generates a temporary polynomial via expanding (1 + x + x^2 + ... + x^n)(1 + y + y^2 + ... + y^n)
    # Later filters out the monomial terms whose degrees in x and y independently exceed 
    # the highest order term across all x^(i + i_0)*y^(j + j_0).
    f = sum(x^i for i in range(terms[0].degree() // 2 + 2))
    f *= f(x=y)
    
    highest_order = terms[0]
    d2 = max(highest_order.degree(x), highest_order.degree(y))

    # Make sure the left block of M corresponds to the coefficients of
    # the monomials that we care about; the ones we do are stored in `terms`
    # and the others are stored in `rest`.
    # We restrict the maximum degree independently in x, y of all terms to be less than that 
    # of the highest order term across all x^(i + i_0)*y^(j + j_0).
    rest = [t for t in list(zip(*list(f)))[1] if max(t.degree(x), t.degree(y)) <= d2 and t not in terms]
    s_terms = terms + rest    

    # Builds the matrix S and calculates n = |det S|.
    X_dim, Y_dim = k^2, k^2
    S = Matrix(ZZ, X_dim, Y_dim)

    # Puts the coefficients corresponding to each monomial in order for every row of S.
    for r, (a, b) in enumerate(prods):
        s_ab = x^a * y^b * p
        coeffs, mons = zip(*list(s_ab))
        s_dict = {k: v for k, v in zip(mons, coeffs)}
        row = vector([s_dict[t] if t in s_dict else 0 for t in terms])
        S[r] = row

    n = det(S)

    # Builds the matrix M as described in the paper, which is k^2 + (k + d)^2 x (k + d)^2
    # The first k^2 rows of M consist of the coefficients of the polynomials s_ab(xX, yY) where
    # 0 <= a, b <= d.
    X_dim, Y_dim = k^2 + (k + d)^2, (k + d)^2

    # Puts the coefficients corresponding to each monomial in order for every row of S.    
    M = Matrix(ZZ, X_dim, Y_dim)
    for r, (a, b) in enumerate(prods):
        s_ab = x^a * y^b * p
        coeffs, mons = zip(*list(s_ab))
        s_dict = {k: v for k, v in zip(mons, coeffs)}
        row = vector([s_dict[t] * t(x=X, y=Y) if t in s_dict else 0 for t in s_terms])
        M[r] = row

    # The next (k + d)^2 rows consist of the coefficients of the polynomials r_ab where
    # 0 <= a, b <= k + d.  Again, the coefficients for each r_ab are inserted in order corresponding
    # To each monomial term.

    for r, (i, j) in zip(range(k^2, X_dim), prods_kd):
        r_ab = x^i * y^j * n
        coeffs, mons = zip(*list(r_ab))
        r_dict = {k: v for k, v in zip(mons, coeffs)}
        row = vector([n * t(x=X, y=Y) if t in r_dict else 0 for t in s_terms])
        M[r] = row

    # Coron describes a triangularization algorithm to triangularize M, but claims that obtaining the
    # Hermite normal form of M works as well, so we do the latter since Sage already has it implemented.
    M = M.hermite_form()

    # As mentioned above, `rest` contains the monomials other than the k^2 ones we chose at the beginning.
    l = len(rest)

    # Performs LLL on L_2
    L_2 = M[list(range(k^2, k^2 + l)), list(range(k^2, k^2 + l))].LLL()

    # The first row of the LLL-reduced L_2 contains a short vector of coefficients b_1
    # corresponding to the coefficients of a polynomial h(x, y) that is not a multiple of p(x, y).
    # Irreducibility of p(x, y) implies that p(x, y) and h(x, y) are algebraically independent 
    # and that they share a root (x_0, y_0).

    # Builds h(x, y) by summing the products of monomials and their coefficient terms, and dividing out by 
    # the extra factors of X^i*Y^j.
    h = sum(coeff * term // (X^term.degree(x) * Y^term.degree(y)) for (coeff, term) in zip(L_2[0], rest))

    # Takes the resultant of h(x, y) and p(x, y).
    q = h.resultant(p, variable=y)
    
    # Obtains the roots x_i of q as a univariate polynomial in x over Z if they exist.  Sage implements this via .roots()
    # Then finds roots for q(x_i, y) as a univariate polynomial in y over Z if they exist.
    roots_x = q.univariate_polynomial().roots(multiplicities=False)

    roots_y = []
    for x_0 in roots_x:
        y_0 = p(x=x_0).univariate_polynomial().roots(multiplicities=False)
        roots_y.append(y_0[0] if y_0 else None)

    if debug and len(roots_x) > 0 and len(roots_y) > 0:
        print(f"Found roots for p:  x = {roots_x}, y = {roots_y}.")

    return roots_x, roots_y

def coron(pol, X, Y, k=2, debug=False):
    """
    Returns all small roots of pol.
    Applies Coron's reformulation of Coppersmith's algorithm for finding small
    integer roots of bivariate polynomials modulo an integer.
    Args:
        pol: The polynomial to find small integer roots of.
        X: Upper limit on x.
        Y: Upper limit on y.
        k: Determines size of lattice. Increase if the algorithm fails.
        debug: Turn on for debug print stuff.
    Returns:
        A list of successfully found roots [(x0,y0), ...].
    Raises:
        ValueError: If pol is not bivariate
    """

    if pol.nvariables() != 2:
        raise ValueError("pol is not bivariate")

    P.<x,y> = PolynomialRing(ZZ)
    pol = pol(x,y)

    # Handle case where pol(0,0) == 0
    xoffset = 0

    while pol(xoffset,0) == 0:
        xoffset += 1

    pol = pol(x+xoffset,y)

    # Handle case where gcd(pol(0,0),X*Y) != 1
    while gcd(pol(0,0), X) != 1:
        X = next_prime(X, proof=False)

    while gcd(pol(0,0), Y) != 1:
        Y = next_prime(Y, proof=False)

    pol = P(pol/gcd(pol.coefficients())) # seems to be helpful
    p00 = pol(0,0)
    delta = max(pol.degree(x),pol.degree(y)) # maximum degree of any variable

    W = max(abs(i) for i in pol(x*X,y*Y).coefficients())
    u = W + ((1-W) % abs(p00))
    N = u*(X*Y)^k # modulus for polynomials

    # Construct polynomials
    p00inv = inverse_mod(p00,N)
    polq = P(sum((i*p00inv % N)*j for i,j in zip(pol.coefficients(),
                                                 pol.monomials())))
    polynomials = []
    for i in range(delta+k+1):
        for j in range(delta+k+1):
            if 0 <= i <= k and 0 <= j <= k:
                polynomials.append(polq * x^i * y^j * X^(k-i) * Y^(k-j))
            else:
                polynomials.append(x^i * y^j * N)

    # Make list of monomials for matrix indices
    monomials = []
    for i in polynomials:
        for j in i.monomials():
            if j not in monomials:
                monomials.append(j)
    monomials.sort()

    # Construct lattice spanned by polynomials with xX and yY
    L = matrix(ZZ,len(monomials))
    for i in range(len(monomials)):
        for j in range(len(monomials)):
            L[i,j] = polynomials[i](X*x,Y*y).monomial_coefficient(monomials[j])

    # makes lattice upper triangular
    # probably not needed, but it makes debug output pretty
    L = matrix(ZZ,sorted(L,reverse=True))

    if debug:
        print("Bitlengths of matrix elements (before reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    L = L.LLL()

    if debug:
        print("Bitlengths of matrix elements (after reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    roots = []

    for i in range(L.nrows()):
        if debug:
            print("Trying row {}".format(i))

        # i'th row converted to polynomial dividing out X and Y
        pol2 = P(sum(map(mul, zip(L[i],monomials)))(x/X,y/Y))

        r = pol.resultant(pol2, y)

        if r.is_constant(): # not independent
            continue

        for x0, _ in r.univariate_polynomial().roots():
            if x0-xoffset in [i[0] for i in roots]:
                continue
            if debug:
                print("Potential x0:",x0)
            for y0, _ in pol(x0,y).univariate_polynomial().roots():
                if debug:
                    print("Potential y0:",y0)
                if (x0-xoffset,y0) not in roots and pol(x0,y0) == 0:
                    roots.append((x0-xoffset,y0))
    return roots

from sage.all import *
import itertools

# display matrix picture with 0 and X
# references: https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage
def matrix_overview(BB, bound):
  for ii in range(BB.dimensions()[0]):
    a = ('%02d ' % ii)
    for jj in range(BB.dimensions()[1]):
      a += ' ' if BB[ii,jj] == 0 else 'X'
      if BB.dimensions()[0] < 60:
        a += ' '
    if BB[ii, ii] >= bound:
      a += '~'
    print(a)

def jochemsz_may_trivariate(pol, XX, YY, ZZ, WW, tau, mm):
  '''
  Implementation of Finding roots of trivariate polynomial [1].
  Thanks @Bono_iPad
  References: 
    [1] Ellen Jochemsz and Alexander May. "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants"
  '''
  tt = floor(mm * tau)
  cond = XX^(7 + 9*tau + 3*tau^2) * (YY*ZZ)^(5+9/2*tau) < WW^(3 + 3*tau)
  print ('[+] Bound check: X^{7+9tau+3tau^2} * (YZ)^{5+9/2tau} < W^{3+3tau}:', )
  if cond:
    print ('OK')
  else:
    print ('NG')

  RR = WW * XX^(2*(mm-1)+tt) * (YY*ZZ)^(mm-1)
  # Polynomial constant coefficient (a_0) must be 1
  # XXX: can a_0 be zero?
  f_ = pol
  a0 = f_.constant_coefficient()

  if a0 != 0:
    F = Zmod(RR)
    PK = PolynomialRing(F, 'xs, ys, zs', order='lex')
    f_ = PR(PK(f_) * F(a0)^-1)

  # Construct set `S` (cf.[1] p.8)
  S = set()
  for i2, i3 in itertools.product(range(0, mm), repeat=2):
    for i1 in range(0, 2*(mm-1) - (i2 + i3) + tt + 1):
      S.add(x^i1 * y^i2 * z^i3)
  S = sorted(S)

  # Construct set `M` (cf.[1] p.8)
  M = set()
  for i2, i3 in itertools.product(range(0, mm + 1), repeat=2):
    for i1 in range(0, 2*mm - (i2 + i3) + tt + 1):
      M.add(x^i1 * y^i2 * z^i3)
  M_S = sorted(M - set(S))
  M = sorted(M)

  # Construct polynomial `g`, `g'` for basis of lattice
  g = []
  g_ = []
  for monomial in S:
    i1 = monomial.degree(x)
    i2 = monomial.degree(y)
    i3 = monomial.degree(z)
    g += [monomial * f_ * XX^(2*(mm-1)+tt-i1) * YY^(mm-1-i2) * ZZ^(mm-1-i3)]

  for monomial in M_S:
    g_ += [monomial * RR]

  # Construct Lattice from `g`, `g'`
  monomials = []
  G = g + g_
  for g_poly in G:
    monomials += g_poly.monomials()
  monomials = sorted(set(monomials))
  assert len(monomials) == len(G)
  dims = len(monomials)
  M = Matrix(IntegerRing(), dims)
  for i in range(dims):
    M[i, 0] = G[i](0, 0, 0)
    for j in range(dims):
      if monomials[j] in G[i].monomials():
        M[i, j] = G[i].monomial_coefficient(monomials[j]) * monomials[j](XX, YY, ZZ)
  matrix_overview(M, 10)
  print() 
  print('=' * 128)
  print()

  # LLL

  B = M.LLL()
  matrix_overview(B, 10)

  # Re-construct polynomial `H_i` from Reduced-lattice
  H = [(i, 0) for i in range(dims)]
  H = dict(H)
  for j in range(dims):
    for i in range(dims):
      H[i] += PR((monomials[j] * B[i, j]) / monomials[j](XX, YY, ZZ))

  PX = PolynomialRing(IntegerRing(), 'xn')
  xn = PX.gen()
  PY = PolynomialRing(IntegerRing(), 'yn')
  yn = PX.gen()
  PZ = PolynomialRing(IntegerRing(), 'zn')
  zn = PX.gen()

  # Solve for `x`
  r1 = H[1].resultant(pol, y)
  r2 = H[2].resultant(pol, y)
  r3 = r1.resultant(r2, z)
  x_roots = map(lambda t: t[0], r3.subs(x=xn).roots())
  assert len(x_roots) > 0
  if len(x_roots) == 1 and x_roots[0] == 0:
    print ('[-] Can\'t find non-trivial solution for `x`')
    return 0, 0, 0
  x_root = x_roots[0]
  print ('[+] Found x0 = %d' % x_root)

  # Solve for `z`
  r1_ = r1.subs(x=x_root)
  r2_ = r2.subs(x=x_root)
  z_roots = map(lambda t: t[0], gcd(r1_, r2_).subs(z=zn).roots())
  assert len(z_roots) > 0
  if len(z_roots) == 1 and z_roots[0] == 0:
    print ('[-] Can\'t find non-trivial solution for `z`')
    return 0, 0, 0
  z_root = z_roots[0]
  print ('[+] Found z0 = %d' % z_root)

  # Solve for `y`
  y_roots = map(lambda t: t[0], H[1].subs(x=x_root, z=z_root).subs(y=yn).roots())
  assert len(y_roots) > 0
  if len(y_roots) == 1 and y_roots[0] == 0:
    print ('[-] Can\'t find non-trivial solution for `y`')
    return 0, 0, 0
  y_root = y_roots[0]
  print ('[+] Found y0 = %d' % y_root)
  assert pol(x_root, y_root, z_root) == 0
  return (x_root, y_root, z_root)


if __name__ == '__main__':
  # Sample Implementation: small secret exponents attack for Common Prime RSA proposed at [1]

  # PlaidCTF 2017: Common
  n=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
  e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
  c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115

  gamma = 0.7
  delta = 0.46

  PR = PolynomialRing(ZZ, 'x, y, z')
  x, y, z = PR.gens()

  # Maximal value of solution `x0`, `y0`, `z0`
#   XX = floor(n^delta)
#   YY = floor(n^(delta + 0.5 - gamma))
#   ZZ = YY
  XX = 2**460
  YY = 2**228
  ZZ = 2**460

  # Norm of polynomial as vector representation
  WW = floor(n^(2 + 2*delta - 2*gamma))

  # Some Non-negative real (cf. [1] p.13)
  tau = (1/2 + gamma - 4*delta) / (2*delta)

  # Powering degree
  mm = 2

  # Target polynomial
#   P.<x,y,z> = PolynomialRing(ZZ)
  pol=-x*y + n*x + n-e*z
  x0, y0, z0 = jochemsz_may_trivariate(pol, XX, YY, ZZ, WW, tau, mm)
  print(x0,y0,z0)
N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115
# P.<x, y> = PolynomialRing(Zmod(e))
# f = 1 + x * (N/y-1)
# P.<x, y> = PolynomialRing(Zmod(e))
# g=-x*y + N*x + N
P.<x,y,z> = PolynomialRing(ZZ)
g=-x*y + N*x + N-e*z
resg = small_roots(g, bounds=(2**460, 2**228,x**460), m=4)